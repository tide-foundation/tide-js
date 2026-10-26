// Heuristic bottleneck analysis over client step summaries and server evidence.
// Each rule is a fixed threshold; the report prints the raw numbers next to every conclusion.

import type { StepSummary } from "../engine.js";
import type { Inventory, StepServer } from "./collectors.js";

export const RULES = {
  cpuPct: 80,            // container or Postgres CPU, % of limit
  memPct: 80,            // container memory, % of limit
  pgMemPct: 90,
  connPct: 80,           // Postgres active / max connections
  iopsPct: 80,
  pgCreditsMin: 30,      // Burstable CPU credits left
  growth: 2,             // p95 growth over the baseline step
  minSamples: 3,         // log-derived p95 needs this many samples in both steps
  clientCpuPct: 80,
  clientQueueMs: 2000,
  threadPoolQueue: 10,
  errorLinesMin: 10,
};

export type Side = "client" | "server";

export interface Suspect {
  component: string;
  side: Side;
  metric: string;
  step: number;          // first step where it crossed
  value: number;
  threshold: string;
  severity: number;      // higher is worse; ties broken by step
  evidence: string;
}

const PHASE_HINT: Record<string, string> = {
  enclave_load: "home ORK serving the enclave + TideCloak authorize",
  signup_form: "browser / enclave UI",
  email_step: "enclave UI + ORK reservation",
  keygen_wait: "ORK keygen fan-out (GenShard/SetCMK/Commit) incl. master SubmitUser",
  fbl_submit: "TideCloak first-broker-login",
  sign_in_to_callback: "ORK Convert/Authenticate + TideCloak broker",
  token_ms: "TideCloak token mint incl. ORK PreSign/Sign",
  create_realm_ms: "TideCloak admin + Postgres",
};

function role(inv: Inventory | null, app: string): string {
  const a = inv?.apps.find((x) => x.name === app);
  return a ? `${a.role} ${app}` : app;
}

function opComponent(inv: Inventory | null, app: string, op: string): string {
  if (op === "Master.SubmitUser") return `master ORK SubmitUser (${app})`;
  if (op.startsWith("Subscription.")) return `payer ${op} (${app})`;
  return `${role(inv, app)} ${op}`;
}

const SIG_COMPONENT: Record<string, (app: string) => string> = {
  sqlite_locked: (a) => `SQLite store (${a})`,
  sqlite_malformed: (a) => `SQLite store (${a})`,
  uid_missing: (a) => `master ORK / Postgres (${a})`,
  stmt_timeout: (a) => `master ORK / Postgres (${a})`,
  npgsql_timeout: (a) => `master ORK / Postgres (${a})`,
  uid_duplicate: (a) => `master ORK SubmitUser concurrent UID insert (${a}, see master-libs PR #30)`,
  pg_unique_violation: (a) => `Postgres unique violation (${a})`,
  vendor_already_created: (a) => `payer (${a})`,
  vendor_keygen_failed: (a) => `payer (${a})`,
  unhandled_exception: (a) => a,
};

export function findSuspects(client: StepSummary[], server: StepServer[], inv: Inventory | null): Suspect[] {
  const out: Suspect[] = [];
  const add = (s: Suspect) => out.push(s);
  const base = client[0];
  const baseServer = server.find((x) => x.step === base?.step) ?? null;

  for (const st of client) {
    // ---- client
    if (st.client.cpuAvg !== null && st.client.cpuAvg > RULES.clientCpuPct) {
      add({ component: "client (load machine CPU)", side: "client", metric: "cpu avg %", step: st.step, value: st.client.cpuAvg, threshold: `> ${RULES.clientCpuPct}%`, severity: 3, evidence: `client CPU avg ${st.client.cpuAvg}% (max ${st.client.cpuMax}%)` });
    }
    for (const o of st.ops) {
      if (o.dropped > 0 || (o.queueWaitP95 ?? 0) > RULES.clientQueueMs) {
        add({ component: "client (browser/HTTP pool)", side: "client", metric: `${o.op} queue`, step: st.step, value: o.queueWaitP95 ?? 0, threshold: `queue wait p95 > ${RULES.clientQueueMs}ms or drops`, severity: 3, evidence: `${o.op}: queue wait p95 ${o.queueWaitP95}ms, ${o.dropped} dropped` });
      }
      const b = base?.ops.find((x) => x.op === o.op);
      if (!b || st.step === base.step) continue;
      for (const [ph, v] of Object.entries(o.phaseP95)) {
        const bv = b.phaseP95[ph];
        if (v !== null && bv && v > RULES.growth * bv) {
          add({ component: `phase ${o.op}.${ph} (${PHASE_HINT[ph] ?? "?"})`, side: "server", metric: "phase p95 growth", step: st.step, value: v, threshold: `> ${RULES.growth}x baseline ${bv}ms`, severity: 1, evidence: `${o.op}.${ph} p95 ${v}ms vs ${bv}ms at step ${base.step} (${(v / bv).toFixed(1)}x)` });
        }
      }
    }

    const sv = server.find((x) => x.step === st.step);
    if (!sv) continue;

    // ---- containers
    for (const [app, m] of Object.entries(sv.apps)) {
      if (m.cpuPctMax !== null && m.cpuPctMax > RULES.cpuPct) add({ component: role(inv, app), side: "server", metric: "cpu % of limit", step: st.step, value: m.cpuPctMax, threshold: `> ${RULES.cpuPct}%`, severity: 3, evidence: `${app} CPU max ${m.cpuPctMax}% avg ${m.cpuPctAvg}% of ${m.limitCores} cores` });
      if (m.memPctMax !== null && m.memPctMax > RULES.memPct) add({ component: role(inv, app), side: "server", metric: "memory % of limit", step: st.step, value: m.memPctMax, threshold: `> ${RULES.memPct}%`, severity: 2, evidence: `${app} memory max ${m.memPctMax}%` });
      if ((m.restarts ?? 0) > 0) add({ component: role(inv, app), side: "server", metric: "restarts", step: st.step, value: m.restarts!, threshold: "> 0", severity: 5, evidence: `${app} restart count +${m.restarts}` });
    }
    for (const e of sv.logs?.system ?? []) {
      if (/Terminated|BackOff|Crashing/i.test(e.reason)) add({ component: role(inv, e.app), side: "server", metric: `system ${e.reason}`, step: st.step, value: e.n, threshold: "> 0", severity: 5, evidence: `${e.app} ${e.reason} x${e.n}${e.exitCodes ? ` exit ${e.exitCodes}` : ""}` });
    }

    // ---- Postgres
    const pg = sv.pg;
    if (pg) {
      const pgAdd = (metric: string, value: number | null, thr: number, sev: number, cmp: "gt" | "lt" = "gt") => {
        if (value === null) return;
        if (cmp === "gt" ? value > thr : value < thr) add({ component: "Postgres dauthme-staging", side: "server", metric, step: st.step, value, threshold: `${cmp === "gt" ? ">" : "<"} ${thr}`, severity: sev, evidence: `postgres ${metric} ${value}` });
      };
      pgAdd("cpu %", pg.cpuPctMax, RULES.cpuPct, 3);
      pgAdd("memory %", pg.memPctMax, RULES.pgMemPct, 2);
      pgAdd("connections % of max", pg.connPctMax, RULES.connPct, 4);
      pgAdd("disk IOPS %", pg.iopsPctMax, RULES.iopsPct, 3);
      pgAdd("cpu credits remaining", pg.cpuCreditsMin, RULES.pgCreditsMin, 3, "lt");
      pgAdd("connections failed", pg.connectionsFailed, 0, 4);
    }

    // ---- log signatures
    for (const [app, sigs] of Object.entries(sv.logs?.signatures ?? {})) {
      for (const [k, n] of Object.entries(sigs)) {
        if (!n) continue;
        if (SIG_COMPONENT[k]) add({ component: SIG_COMPONENT[k](app), side: "server", metric: `log ${k}`, step: st.step, value: n, threshold: "> 0", severity: 4, evidence: `${app}: ${k} x${n}` });
        if (k === "error_lines") {
          const bn = baseServer?.logs?.signatures[app]?.error_lines ?? 0;
          if (st.step !== base?.step && n >= RULES.errorLinesMin && n > RULES.growth * Math.max(1, bn)) add({ component: role(inv, app), side: "server", metric: "error log lines", step: st.step, value: n, threshold: `>= ${RULES.errorLinesMin} and > ${RULES.growth}x baseline ${bn}`, severity: 2, evidence: `${app}: ${n} error lines vs ${bn} at baseline` });
        }
      }
    }

    // ---- ORK execution times vs baseline
    if (baseServer && st.step !== base?.step) {
      for (const r of sv.logs?.exec ?? []) {
        const b = baseServer.logs?.exec.find((x) => x.app === r.app && x.op === r.op);
        if (!b || r.n < RULES.minSamples || b.n < RULES.minSamples || b.p95 <= 0) continue;
        if (r.p95 > RULES.growth * b.p95 && r.p95 >= 50) add({ component: opComponent(inv, r.app, r.op), side: "server", metric: "exec p95 growth", step: st.step, value: r.p95, threshold: `> ${RULES.growth}x baseline ${b.p95}ms`, severity: 2, evidence: `${r.app} ${r.op} p95 ${r.p95}ms (n=${r.n}) vs ${b.p95}ms (n=${b.n})` });
      }
    }

    // ---- Prometheus
    const p = sv.prom;
    if (p) {
      const bp = baseServer?.prom;
      for (const [t, v] of Object.entries(p.outboundP95)) {
        const bv = bp?.outboundP95[t];
        if (st.step !== base?.step && bv && v > RULES.growth * bv) add({ component: t === "payer" ? "payer (outbound from ORKs)" : t === "master" ? "master ORK (outbound from ORKs)" : `peer ${t}`, side: "server", metric: "outbound p95 growth", step: st.step, value: v, threshold: `> ${RULES.growth}x baseline ${bv}ms`, severity: 3, evidence: `ORK -> ${t} p95 ${v}ms vs ${bv}ms` });
      }
      for (const o of p.outbound) if (o.status === "error" && o.count > 0) add({ component: o.target === "payer" ? "payer (outbound errors)" : `${o.target} (outbound errors)`, side: "server", metric: "outbound errors", step: st.step, value: o.count, threshold: "> 0", severity: 3, evidence: `ORK -> ${o.target} errors x${o.count}` });
      if ((p.throttleRejections ?? 0) > 0) add({ component: "ORK throttle", side: "server", metric: "throttle rejections", step: st.step, value: p.throttleRejections!, threshold: "> 0", severity: 3, evidence: `throttle rejections ${p.throttleRejections}` });
      if ((p.semaphoreWaitersMax ?? 0) > 0) add({ component: "ORK sync semaphore", side: "server", metric: "semaphore waiters", step: st.step, value: p.semaphoreWaitersMax!, threshold: "> 0", severity: 2, evidence: `max waiters ${p.semaphoreWaitersMax}, wait p95 ${p.semaphoreWaitP95}ms` });
      if ((p.threadPoolQueueMax ?? 0) > RULES.threadPoolQueue) add({ component: "ORK .NET thread pool", side: "server", metric: "thread pool queue", step: st.step, value: p.threadPoolQueueMax!, threshold: `> ${RULES.threadPoolQueue}`, severity: 3, evidence: `thread pool queue max ${p.threadPoolQueueMax}` });
    }

    // ---- stub routing
    if (sv.stub && !sv.stub.ok) add({ component: "Stripe stub routing", side: "server", metric: "unexpected passthrough", step: st.step, value: Object.values(sv.stub.unexpectedPassthrough).reduce((a, b) => a + b, 0), threshold: "only GET /v1/prices may pass through", severity: 4, evidence: JSON.stringify(sv.stub.unexpectedPassthrough) });
  }
  return out;
}

export interface StepAnalysis {
  step: number;
  label: string;
  ranked: Suspect[];
  first: Suspect | null;
  verdict: string;
  slowestOrk: string | null;
  slowestPhase: string | null;
}

// Keep the earliest crossing per component+metric, up to the step being explained, then rank.
export function analyseStep(all: Suspect[], step: number, label: string, client: StepSummary[], server: StepServer[]): StepAnalysis {
  const best = new Map<string, Suspect>();
  for (const s of all.filter((x) => x.step <= step)) {
    const k = `${s.component}|${s.metric}`;
    const cur = best.get(k);
    if (!cur || s.step < cur.step || (s.step === cur.step && s.value > cur.value)) best.set(k, s);
  }
  // Prefer the value at the explained step for display when it crossed again there.
  for (const s of all.filter((x) => x.step === step)) best.set(`${s.component}|${s.metric}`, { ...s, step: best.get(`${s.component}|${s.metric}`)?.step ?? s.step });
  const ranked = [...best.values()].sort((a, b) => a.step - b.step || b.severity - a.severity);
  const first = ranked[0] ?? null;
  const firstClient = ranked.find((s) => s.side === "client");
  const firstServer = ranked.find((s) => s.side === "server" && !s.component.startsWith("phase "));
  let verdict: string;
  if (!firstClient && !firstServer) verdict = ranked.length ? "server-bound (only client phase timings grew; no server metric crossed a threshold)" : "no threshold crossed: no bottleneck identified at this rate";
  else if (firstClient && (!firstServer || firstClient.step < firstServer.step)) verdict = `client-bound (client crossed first at step ${firstClient.step}: ${firstClient.evidence})`;
  else if (firstServer && (!firstClient || firstServer.step < firstClient.step)) verdict = `server-bound (server crossed first at step ${firstServer.step}: ${firstServer.evidence})`;
  else verdict = `mixed (client and server both crossed at step ${firstClient!.step})`;

  const sv = server.find((x) => x.step === step);
  let slowestOrk: string | null = null;
  const orkRows = (sv?.logs?.exec ?? []).filter((r) => /^sork\d+$/.test(r.app) && /^(Create|Key|Auth|Master\.SubmitUser|Subscription\.Validate)/.test(r.op));
  if (orkRows.length) {
    const top = orkRows.reduce((a, b) => (b.p95 > a.p95 ? b : a));
    slowestOrk = `${top.app} (${top.op} p95 ${top.p95}ms, max ${top.max}ms, n=${top.n})`;
  }
  let slowestPhase: string | null = null;
  const cs = client.find((x) => x.step === step);
  const base = client[0];
  for (const o of cs?.ops ?? []) {
    for (const [ph, v] of Object.entries(o.phaseP95)) {
      if (v === null) continue;
      const bv = base?.ops.find((x) => x.op === o.op)?.phaseP95[ph] ?? null;
      const txt = `${o.op}.${ph} p95 ${v}ms${bv ? ` (${(v / bv).toFixed(1)}x baseline ${bv}ms)` : ""}`;
      const curV = slowestPhase ? parseFloat(/p95 (\d+)/.exec(slowestPhase)?.[1] ?? "0") : -1;
      if (v > curV) slowestPhase = txt;
    }
  }
  return { step, label, ranked, first, verdict, slowestOrk, slowestPhase };
}

// Server-only runs (prepare-realms) get placeholder client steps so the server rules still run.
function placeholderSteps(server: StepServer[]): StepSummary[] {
  return server.map((s) => ({
    step: s.step, kind: s.kind, baseRate: 0, startedAt: s.window.start, endedAt: s.window.end, startMs: Date.parse(s.window.start), endMs: Date.parse(s.window.end), ops: [],
    client: { cpuAvg: null, cpuMax: null, loopLagP95: null, maxQueue: {}, poolBusyAvg: {} },
    flags: { knee: false, break: false, clientBound: false, breakSignatures: [], reasons: [] }, verdict: "ok",
  }));
}

export function analyse(clientIn: StepSummary[], server: StepServer[], inv: Inventory | null): StepAnalysis[] {
  const client = clientIn.length ? clientIn : placeholderSteps(server);
  const all = findSuspects(client, server, inv);
  const out: StepAnalysis[] = [];
  const knee = client.find((s) => s.verdict === "knee");
  const brk = client.find((s) => s.verdict === "break" || s.verdict === "aborted" || s.verdict === "client-bound");
  if (knee) out.push(analyseStep(all, knee.step, `knee (step ${knee.step})`, client, server));
  if (brk) out.push(analyseStep(all, brk.step, `${brk.verdict} (step ${brk.step})`, client, server));
  if (!out.length && client.length) {
    const last = client[client.length - 1];
    out.push(analyseStep(all, last.step, `last step ${last.step} (no knee or break)`, client, server));
  }
  return out;
}

export function analysisMarkdown(list: StepAnalysis[]): string[] {
  const lines: string[] = [
    "## Bottleneck analysis (heuristic)",
    "",
    `Rules: CPU or memory > ${RULES.cpuPct}% of limit, p95 > ${RULES.growth}x the baseline step, any failure signature in the logs, Postgres connections > ${RULES.connPct}% of max, IOPS > ${RULES.iopsPct}%, Burstable credits < ${RULES.pgCreditsMin}, client CPU > ${RULES.clientCpuPct}% or queue wait > ${RULES.clientQueueMs}ms. Suspects are ranked by the step where they first crossed, then severity. These are heuristics; check the raw numbers below each line.`,
    "",
  ];
  if (!list.length) return [...lines, "- no steps to analyse"];
  for (const a of list) {
    lines.push(`### ${a.label}`, "");
    lines.push(`- **verdict:** ${a.verdict}`);
    lines.push(`- **first to cross:** ${a.first ? `${a.first.component}: ${a.first.metric} ${a.first.value} (${a.first.threshold}) at step ${a.first.step}` : "none"}`);
    lines.push(`- **slowest ORK:** ${a.slowestOrk ?? "no ORK timing data"}`);
    lines.push(`- **slowest phase:** ${a.slowestPhase ?? "no phase data"}`);
    lines.push("", "| # | component | metric | first step | value | threshold | evidence |", "|---|---|---|---|---|---|---|");
    a.ranked.slice(0, 15).forEach((s, i) => lines.push(`| ${i + 1} | ${s.component} | ${s.metric} | ${s.step} | ${s.value} | ${s.threshold} | ${s.evidence} |`));
    if (!a.ranked.length) lines.push("| - | none | | | | | |");
    lines.push("");
  }
  return lines;
}
