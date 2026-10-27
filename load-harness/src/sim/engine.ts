// Stepped open-loop ramp. Each step holds a target arrival rate for a fixed time; arrivals
// queue for a pool slot, so a slow server shows up as latency and a busy client as queue wait.

import { Pool } from "./pool.js";
import { ClientMonitor } from "./monitor.js";
import { Jsonl } from "./sink.js";
import { matchSignatures, isBreakSignature, isExpectedSignature, isSoftSignature } from "./signatures.js";
import { percentile, sleep, utcStamp, fmtRate, scrub, truncate } from "./util.js";

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

export interface RampOpts {
  startRate: number;     // base ops per minute at step 1
  factor: number;        // multiply per step (2 = doubling); ignored when add > 0
  add: number;           // add per step instead of multiplying
  maxRate: number;       // stop before exceeding this base rate
  maxSteps: number;
  stepMs: number;
  cooldownMs: number;
}

export interface PlannedStep {
  index: number;   // 1-based
  baseRate: number;
  kind: "ramp" | "confirm";
}

export function planSteps(o: RampOpts): PlannedStep[] {
  const steps: PlannedStep[] = [];
  let rate = o.startRate;
  for (let i = 1; i <= o.maxSteps && rate <= o.maxRate + 1e-9; i++) {
    steps.push({ index: i, baseRate: rate, kind: "ramp" });
    rate = o.add > 0 ? rate + o.add : rate * o.factor;
  }
  return steps;
}

// ---------------------------------------------------------------------------
// Ops and results
// ---------------------------------------------------------------------------

export interface OpOutcome {
  ok: boolean;
  code?: string;
  message?: string;
  status?: number;
  phases?: Record<string, number>;
  extra?: Record<string, unknown>;
  // An outcome that is neither a pass nor a staging failure (seat cap, empty user pool).
  expected?: boolean;
  // A failure caused by the load machine (its browser died), not by staging.
  clientSide?: boolean;
}

export interface OpContext {
  seq: number;
  step: number;
  stop: (reason: string) => void;
  aborted: () => boolean;
  // Browser ops report the browser slot they run on, so a failure on a lost browser is client-side.
  onBrowser?: (lease: { index: number; lost: () => boolean }) => void;
}

export interface OpSpec {
  name: string;
  ratio: number;           // multiplier on the step base rate
  pool: Pool;
  maxQueue: number;        // arrivals beyond this queue depth are dropped as client saturation
  run: (ctx: OpContext) => Promise<OpOutcome>;
}

export interface EventRow {
  ts: string;              // arrival time; the step is the one the op arrived in
  endTs?: string;          // completion time (ts + queueWaitMs + latencyMs)
  runId: string;
  scenario: string;
  op: string;
  step: number;
  stepKind: string;
  targetRate: number;
  seq: number;
  ok: boolean;
  code: string | null;
  signatures: string[];
  expected: boolean;
  dropped: boolean;
  late: boolean;
  queueWaitMs: number;
  latencyMs: number;
  phases: Record<string, number>;
  status?: number;
  message?: string;
  extra?: Record<string, unknown>;
  clientSide?: boolean;    // failed because the load machine's browser died; not a staging error
  browser?: number;        // browser slot the op ran on
}

// ---------------------------------------------------------------------------
// Thresholds and verdicts
// ---------------------------------------------------------------------------

export interface Thresholds {
  kneeP95Mult: number;        // knee when p95 > mult x baseline p95
  kneeThroughput: number;     // knee when on-time completions / arrivals < this
  breakErrorRate: number;     // break when error rate > this
  abortErrorRate: number;     // hard abort on rolling-window error rate
  abortWindowMs: number;
  abortMinSamples: number;
  clientCpuPct: number;       // client bound when average CPU above this
  clientQueueWaitMs: number;  // client bound when queue wait p95 above this
  strictSignatures?: boolean; // break on soft signatures too (old rule)
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  kneeP95Mult: 2,
  kneeThroughput: 0.9,
  breakErrorRate: 0.05,
  abortErrorRate: 0.2,
  abortWindowMs: 30_000,
  abortMinSamples: 5,
  clientCpuPct: 85,
  clientQueueWaitMs: 2000,
};

export interface OpStepStats {
  op: string;
  targetRate: number;
  arrivals: number;
  completed: number;
  ok: number;
  failed: number;
  expected: number;
  dropped: number;
  late: number;
  errorRate: number;
  onTimeRatio: number;
  okPerMin: number;
  p50: number | null;
  p95: number | null;
  p99: number | null;
  queueWaitP95: number | null;
  clientLost?: number;     // failures from lost browsers, excluded from the counts above
  codes: Record<string, number>;
  signatures: Record<string, number>;
  phaseP95: Record<string, number | null>;
}

export type Verdict = "ok" | "knee" | "break" | "client-bound" | "aborted" | "stopped";

export interface StepSummary {
  step: number;
  kind: string;
  baseRate: number;
  startedAt: string;
  endedAt: string;
  startMs: number;
  endMs: number;
  ops: OpStepStats[];
  client: { cpuAvg: number | null; cpuMax: number | null; loopLagP95: number | null; maxQueue: Record<string, number>; poolBusyAvg: Record<string, number> };
  flags: { knee: boolean; break: boolean; clientBound: boolean; breakSignatures: string[]; reasons: string[]; warnings?: Record<string, number> };
  verdict: Verdict;
}

function avg(xs: number[]): number | null {
  return xs.length ? Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 10) / 10 : null;
}

export function summariseOp(rows: EventRow[], op: string, targetRate: number, stepMs: number): OpStepStats {
  const mine = rows.filter((r) => r.op === op);
  const dropped = mine.filter((r) => r.dropped).length;
  const done = mine.filter((r) => !r.dropped);
  const expected = done.filter((r) => r.expected).length;
  const clientLost = done.filter((r) => r.clientSide && !r.expected).length;
  const counted = done.filter((r) => !r.expected && !r.clientSide);
  const ok = counted.filter((r) => r.ok);
  const failed = counted.length - ok.length;
  const late = ok.filter((r) => r.late).length;
  const codes: Record<string, number> = {};
  const sigs: Record<string, number> = {};
  for (const r of done) {
    if (!r.ok && r.code) codes[r.code] = (codes[r.code] ?? 0) + 1;
    for (const s of r.signatures) sigs[s] = (sigs[s] ?? 0) + 1;
  }
  const lat = ok.map((r) => r.latencyMs);
  const phaseNames = new Set<string>();
  ok.forEach((r) => Object.keys(r.phases).forEach((k) => phaseNames.add(k)));
  const phaseP95: Record<string, number | null> = {};
  for (const p of phaseNames) phaseP95[p] = percentile(ok.map((r) => r.phases[p]).filter((v) => typeof v === "number"), 95);
  const arrivals = mine.length - expected - clientLost;
  return {
    op,
    targetRate,
    arrivals: mine.length,
    completed: done.length,
    ok: ok.length,
    failed,
    expected,
    dropped,
    late,
    errorRate: counted.length ? failed / counted.length : 0,
    onTimeRatio: arrivals > 0 ? (ok.length - late) / arrivals : 1,
    okPerMin: stepMs > 0 ? (ok.length * 60_000) / stepMs : 0,
    p50: percentile(lat, 50),
    p95: percentile(lat, 95),
    p99: percentile(lat, 99),
    queueWaitP95: percentile(done.map((r) => r.queueWaitMs), 95),
    ...(clientLost ? { clientLost } : {}),
    codes,
    signatures: sigs,
    phaseP95,
  };
}

// Decide knee / break / client-bound for one step. baselineP95 is per op, from the first step with successes.
export function judgeStep(
  ops: OpStepStats[],
  client: StepSummary["client"],
  baselineP95: Record<string, number>,
  t: Thresholds,
): StepSummary["flags"] {
  const reasons: string[] = [];
  let knee = false;
  let brk = false;
  let clientBound = false;
  const breakSignatures: string[] = [];
  const warnings: Record<string, number> = {};
  for (const o of ops) {
    if (o.arrivals === 0) continue;
    const base = baselineP95[o.op];
    if (base && o.p95 !== null && o.p95 > t.kneeP95Mult * base) {
      knee = true;
      reasons.push(`${o.op}: p95 ${o.p95}ms > ${t.kneeP95Mult}x baseline ${base}ms`);
    }
    if (o.onTimeRatio < t.kneeThroughput && o.arrivals >= 3) {
      knee = true;
      reasons.push(`${o.op}: on-time completions ${(o.onTimeRatio * 100).toFixed(0)}% < ${t.kneeThroughput * 100}%`);
    }
    if (o.errorRate > t.breakErrorRate) {
      brk = true;
      reasons.push(`${o.op}: error rate ${(o.errorRate * 100).toFixed(1)}% > ${t.breakErrorRate * 100}%`);
    }
    for (const [s, n] of Object.entries(o.signatures)) {
      if (!isBreakSignature(s)) continue;
      if (isSoftSignature(s) && !t.strictSignatures) { warnings[s] = (warnings[s] ?? 0) + n; continue; }
      brk = true;
      if (!breakSignatures.includes(s)) breakSignatures.push(s);
    }
    // Losing many browsers in one step means the load machine, not staging, set the limit.
    const lost = o.clientLost ?? 0;
    if (lost && lost / (o.arrivals - o.expected) > 0.25) {
      clientBound = true;
      reasons.push(`${o.op}: ${lost} of ${o.arrivals - o.expected} lost to browser crashes (> 25%)`);
    }
    if (o.dropped > 0) {
      clientBound = true;
      reasons.push(`${o.op}: ${o.dropped} arrivals dropped, client queue full`);
    }
    if (o.queueWaitP95 !== null && o.queueWaitP95 > t.clientQueueWaitMs) {
      clientBound = true;
      reasons.push(`${o.op}: queue wait p95 ${o.queueWaitP95}ms > ${t.clientQueueWaitMs}ms (pool too small)`);
    }
  }
  if (breakSignatures.length) reasons.push(`server failure signatures: ${breakSignatures.join(",")}`);
  if (Object.keys(warnings).length) reasons.push(`warnings: ${Object.entries(warnings).map(([k, n]) => `${k} x${n}`).join(", ")}`);
  if (client.cpuAvg !== null && client.cpuAvg > t.clientCpuPct) {
    clientBound = true;
    reasons.push(`client CPU avg ${client.cpuAvg}% > ${t.clientCpuPct}%`);
  }
  return { knee, break: brk, clientBound, breakSignatures, reasons, ...(Object.keys(warnings).length ? { warnings } : {}) };
}

export function verdictOf(f: StepSummary["flags"]): Verdict {
  if (f.break) return "break";
  if (f.clientBound) return "client-bound";
  if (f.knee) return "knee";
  return "ok";
}

// Exponential gap for Poisson arrivals, or a fixed gap for uniform.
export function nextGapMs(ratePerMin: number, mode: "poisson" | "uniform", rnd = Math.random): number {
  if (ratePerMin <= 0) return Infinity;
  const mean = 60_000 / ratePerMin;
  if (mode === "uniform") return mean;
  return -Math.log(1 - rnd()) * mean;
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export interface EngineOpts {
  runId: string;
  scenario: string;
  steps: PlannedStep[];
  stepMs: number;
  cooldownMs: number;
  drainMs: number;
  arrival: "poisson" | "uniform";
  thresholds: Thresholds;
  events: Jsonl;
  stepsLog: Jsonl;
  monitor: ClientMonitor;
  log: (s: string) => void;
  secrets?: () => string[];
  // Best-effort hooks around each step (Stripe stub snapshots). Errors are swallowed.
  onStepStart?: (step: number) => Promise<void>;
  onStepEnd?: (step: number) => Promise<void>;
}

export interface EngineResult {
  steps: StepSummary[];
  abortReason: string | null;
  stopReason: string | null;
  baselineP95: Record<string, number>;
}

export class Engine {
  private abortReason: string | null = null;
  private stopReason: string | null = null;
  private seq = 0;
  private recent: Array<{ t: number; bad: boolean }> = [];

  constructor(private o: EngineOpts, private ops: OpSpec[]) {}

  abort(reason: string): void {
    if (this.abortReason) return;
    this.abortReason = reason;
    this.o.log(`ABORT: ${reason}`);
  }

  stop(reason: string): void {
    if (this.stopReason || this.abortReason) return;
    this.stopReason = reason;
    this.o.log(`STOP: ${reason}`);
  }

  private halted(): boolean {
    return !!this.abortReason || !!this.stopReason;
  }

  private trackAbort(row: EventRow): void {
    if (row.dropped || row.expected || row.clientSide) return;
    const now = Date.now();
    this.recent.push({ t: now, bad: !row.ok });
    const cutoff = now - this.o.thresholds.abortWindowMs;
    while (this.recent.length && this.recent[0].t < cutoff) this.recent.shift();
    const n = this.recent.length;
    if (n >= this.o.thresholds.abortMinSamples) {
      const bad = this.recent.filter((r) => r.bad).length;
      if (bad / n > this.o.thresholds.abortErrorRate) {
        this.abort(`rolling ${this.o.thresholds.abortWindowMs / 1000}s error rate ${((bad / n) * 100).toFixed(0)}% > ${this.o.thresholds.abortErrorRate * 100}% (${bad}/${n})`);
      }
    }
  }

  private async fire(op: OpSpec, step: PlannedStep, stepEnd: number, rows: EventRow[]): Promise<void> {
    const seq = ++this.seq;
    const targetRate = step.baseRate * op.ratio;
    const base: Omit<EventRow, "ok" | "code" | "signatures" | "expected" | "dropped" | "late" | "queueWaitMs" | "latencyMs" | "phases"> = {
      ts: new Date().toISOString(),
      runId: this.o.runId,
      scenario: this.o.scenario,
      op: op.name,
      step: step.index,
      stepKind: step.kind,
      targetRate,
      seq,
    };
    if (op.pool.queued >= op.maxQueue) {
      const row: EventRow = { ...base, ok: false, code: "CLIENT_DROPPED", signatures: [], expected: false, dropped: true, late: false, queueWaitMs: 0, latencyMs: 0, phases: {} };
      rows.push(row);
      this.o.events.write(row);
      return;
    }
    const q0 = Date.now();
    const release = await op.pool.acquire();
    const queueWaitMs = Date.now() - q0;
    const t0 = Date.now();
    let out: OpOutcome;
    let lease: { index: number; lost: () => boolean } | undefined;
    try {
      if (this.abortReason) out = { ok: false, code: "SKIPPED_ABORT", expected: true };
      else out = await op.run({ seq, step: step.index, stop: (r) => this.stop(r), aborted: () => !!this.abortReason, onBrowser: (l) => { lease = l; } });
    } catch (e) {
      out = { ok: false, code: "DRIVER_CRASH", message: (e as Error)?.message ?? String(e) };
    } finally {
      release();
    }
    const latencyMs = Date.now() - t0;
    const secrets = this.o.secrets ? this.o.secrets() : [];
    const message = out.message ? truncate(scrub(out.message, secrets), 600) : undefined;
    const sigs = out.ok ? [] : matchSignatures(`${out.code ?? ""} ${message ?? ""}`).map((s) => s.id);
    const expected = !!out.expected || (sigs.length > 0 && sigs.every((s) => isExpectedSignature(s)));
    // A harness exception or a failure on a browser that died mid-op is the load machine's fault.
    const clientSide = !out.ok && (!!out.clientSide || out.code === "DRIVER_CRASH" || (!!out.code && out.code !== "SKIPPED_ABORT" && !!lease?.lost()));
    const row: EventRow = {
      ...base,
      ok: out.ok,
      code: out.ok ? null : out.code ?? "UNKNOWN",
      signatures: sigs,
      expected,
      dropped: false,
      late: Date.now() > stepEnd,
      queueWaitMs,
      latencyMs,
      phases: out.phases ?? {},
      status: out.status,
      message,
      extra: out.extra,
      endTs: new Date().toISOString(),
      ...(clientSide ? { clientSide } : {}),
      ...(lease ? { browser: lease.index } : {}),
    };
    rows.push(row);
    this.o.events.write(row);
    this.trackAbort(row);
  }

  private async runStep(step: PlannedStep): Promise<StepSummary> {
    await this.o.onStepStart?.(step.index).catch(() => undefined);
    const rows: EventRow[] = [];
    const startMs = Date.now();
    const stepEnd = startMs + this.o.stepMs;
    const inflight: Promise<void>[] = [];
    this.o.log(`STEP ${step.index} (${step.kind}) START ${utcStamp()} base=${fmtRate(step.baseRate)} ` +
      this.ops.map((op) => `${op.name}=${fmtRate(step.baseRate * op.ratio)}`).join(" "));

    await Promise.all(this.ops.map(async (op) => {
      const rate = step.baseRate * op.ratio;
      let next = startMs + nextGapMs(rate, this.o.arrival);
      while (!this.halted()) {
        if (next >= stepEnd) break;
        const wait = next - Date.now();
        // Wake at least once a second so an abort is noticed quickly.
        if (wait > 1000) { await sleep(1000); continue; }
        await sleep(wait);
        if (this.halted()) break;
        inflight.push(this.fire(op, step, stepEnd, rows));
        next += nextGapMs(rate, this.o.arrival);
      }
    }));
    const tailWait = stepEnd - Date.now();
    if (tailWait > 0 && !this.halted()) await sleep(tailWait);

    // Let in-flight work finish so every arrival has a terminal timing.
    const drained = await Promise.race([
      Promise.allSettled(inflight).then(() => true),
      sleep(this.o.drainMs).then(() => false),
    ]);
    if (!drained) this.o.log(`step ${step.index}: drain timeout, ${inflight.length} arrivals, some still running`);
    const endMs = Date.now();
    this.o.log(`STEP ${step.index} END ${utcStamp()}`);
    await this.o.onStepEnd?.(step.index).catch(() => undefined);

    const ops = this.ops.map((op) => summariseOp(rows, op.name, step.baseRate * op.ratio, this.o.stepMs));
    const win = this.o.monitor.window(startMs, endMs);
    const maxQueue: Record<string, number> = {};
    const poolBusyAvg: Record<string, number> = {};
    for (const op of this.ops) {
      maxQueue[op.pool.name] = Math.max(0, ...win.map((s) => s.pools[op.pool.name]?.queued ?? 0));
      poolBusyAvg[op.pool.name] = avg(win.map((s) => s.pools[op.pool.name]?.busy ?? 0)) ?? 0;
    }
    const client = {
      cpuAvg: avg(win.map((s) => s.cpuPct)),
      cpuMax: win.length ? Math.max(...win.map((s) => s.cpuPct)) : null,
      loopLagP95: percentile(win.map((s) => s.loopLagMs), 95),
      maxQueue,
      poolBusyAvg,
    };
    return {
      step: step.index,
      kind: step.kind,
      baseRate: step.baseRate,
      startedAt: new Date(startMs).toISOString(),
      endedAt: new Date(endMs).toISOString(),
      startMs,
      endMs,
      ops,
      client,
      flags: { knee: false, break: false, clientBound: false, breakSignatures: [], reasons: [] },
      verdict: "ok",
    };
  }

  async run(): Promise<EngineResult> {
    const results: StepSummary[] = [];
    const baseline: Record<string, number> = {};
    let lastGood: PlannedStep | null = null;
    const queue = [...this.o.steps];
    let confirmed = false;

    while (queue.length && !this.halted()) {
      const step = queue.shift()!;
      const s = await this.runStep(step);
      for (const o of s.ops) if (baseline[o.op] === undefined && o.p95 !== null) baseline[o.op] = o.p95;
      s.flags = judgeStep(s.ops, s.client, baseline, this.o.thresholds);
      s.verdict = this.abortReason ? "aborted" : this.stopReason ? "stopped" : verdictOf(s.flags);
      results.push(s);
      this.o.stepsLog.write(s);
      this.o.log(`step ${s.step} verdict=${s.verdict}${s.flags.reasons.length ? " (" + s.flags.reasons.join("; ") + ")" : ""}`);

      if (this.halted()) break;
      if (step.kind === "confirm") { confirmed = true; break; }
      if (s.verdict === "client-bound") {
        this.stop("client machine is the bottleneck; raise --browser-pool / --concurrency or add load machines before reading this as a staging limit");
        break;
      }
      if (s.verdict === "break") {
        if (lastGood && !confirmed) {
          queue.length = 0;
          queue.push({ index: step.index + 1, baseRate: lastGood.baseRate, kind: "confirm" });
          this.o.log(`break at step ${step.index}; one confirmation step at last good rate ${fmtRate(lastGood.baseRate)} after cooldown`);
        } else {
          break;
        }
      } else if (s.verdict === "ok" || s.verdict === "knee") {
        lastGood = step;
      }
      if (queue.length && this.o.cooldownMs > 0) {
        this.o.log(`cooldown ${Math.round(this.o.cooldownMs / 1000)}s`);
        const until = Date.now() + this.o.cooldownMs;
        while (Date.now() < until && !this.abortReason) await sleep(Math.min(1000, until - Date.now()));
      }
    }
    return { steps: results, abortReason: this.abortReason, stopReason: this.stopReason, baselineP95: baseline };
  }
}
