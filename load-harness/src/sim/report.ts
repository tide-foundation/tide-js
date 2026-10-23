// Summary report (JSON + Markdown), the server-side queries for the run window, and the manual cleanup checklist.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import type { EngineResult, StepSummary } from "./engine.js";
import type { Manifest } from "./sink.js";
import { fmtRate } from "./util.js";
import { SIGNATURES } from "./signatures.js";

export function kql(startIso: string, endIso: string): string {
  return [
    "// ORK and TideCloak failure signatures per minute (Tide-Staging Log Analytics)",
    "ContainerAppConsoleLogs_CL",
    `| where TimeGenerated between (datetime(${startIso}) .. datetime(${endIso}))`,
    `| where ContainerAppName_s startswith "sork" or ContainerAppName_s startswith "tidecloak"`,
    "| summarize sqlite_locked=countif(Log_s has \"database is locked\"),",
    "            submit_user=countif(Log_s has \"SubmitUser\"),",
    "            uid_missing=countif(Log_s has \"could not find uid\"),",
    "            stmt_timeout=countif(Log_s has \"statement timeout\"),",
    "            vendor_already=countif(Log_s has \"VENDOR_ALREADY_CREATED\"),",
    "            seat_cap=countif(Log_s has \"exceeded its total user count\"),",
    "            keygen_failed=countif(Log_s has \"VENDOR_KEYGEN_FAILED\")",
    "  by ContainerAppName_s, bin(TimeGenerated, 1m)",
    "| order by TimeGenerated asc",
    "",
    "// ORK restarts and crashes",
    "ContainerAppSystemLogs_CL",
    `| where TimeGenerated between (datetime(${startIso}) .. datetime(${endIso}))`,
    `| where ContainerAppName_s startswith "sork"`,
    "| where Reason_s in (\"BackOff\", \"ContainerTerminated\", \"ContainerCrashing\", \"ProbeFailed\") or Log_s has \"exit code\"",
    "| project TimeGenerated, ContainerAppName_s, Reason_s, Log_s",
  ].join("\n");
}

export function promql(job: string): string[] {
  return [
    `sum by (target, status) (rate(tide_ork_outbound_duration_seconds_count{job="${job}"}[1m]))`,
    `sum by (target) (rate(tide_ork_outbound_duration_seconds_sum{job="${job}"}[1m])) / sum by (target) (rate(tide_ork_outbound_duration_seconds_count{job="${job}"}[1m]))`,
    `sum by (op) (rate(tide_ork_protocol_duration_seconds_count{job="${job}"}[1m]))`,
    `sum by (op) (rate(tide_ork_protocol_duration_seconds_sum{job="${job}"}[1m])) / sum by (op) (rate(tide_ork_protocol_duration_seconds_count{job="${job}"}[1m]))`,
    `sum(rate(tide_ork_throttle_rejections_total{job="${job}"}[1m]))`,
    `max(tide_ork_sync_semaphore_waiters{job="${job}"})`,
  ];
}

export interface Ceiling { op: string; lastOk: number | null; knee: number | null; brk: number | null; clientBound: number | null }

export function ceilings(steps: StepSummary[]): Ceiling[] {
  const ops = new Set<string>();
  steps.forEach((s) => s.ops.forEach((o) => ops.add(o.op)));
  return [...ops].map((op) => {
    const c: Ceiling = { op, lastOk: null, knee: null, brk: null, clientBound: null };
    for (const s of steps) {
      if (s.kind === "confirm") continue;
      const st = s.ops.find((o) => o.op === op);
      if (!st || st.arrivals === 0) continue;
      if (s.verdict === "ok" || s.verdict === "knee") c.lastOk = st.targetRate;
      if (s.verdict === "knee" && c.knee === null) c.knee = st.targetRate;
      if (s.verdict === "break" && c.brk === null) c.brk = st.targetRate;
      if (s.verdict === "client-bound" && c.clientBound === null) c.clientBound = st.targetRate;
    }
    return c;
  });
}

export function cleanupChecklist(m: Manifest, manifestPath: string): string {
  const realms = m.realms;
  const created = m.users.filter((u) => u.status === "created");
  const attempted = m.users.length;
  const customers = realms.map((r) => r.customerId).filter(Boolean);
  const subs = realms.map((r) => r.subscriptionId).filter(Boolean);
  const lines = [
    `CLEANUP CHECKLIST (manual, nothing below was done automatically)`,
    `run ${m.runId} on ${m.target} (${m.tcBase}); full list in ${manifestPath}`,
    ``,
    `[ ] 1. Delete ${realms.length} realm(s) in the TideCloak admin console (or DELETE /admin/realms/<name>):`,
    ...realms.map((r) => `       - ${r.realm}  (${r.purpose}, ${r.status}${r.error ? ", " + r.error.slice(0, 80) : ""})`),
    `[ ] 2. Stripe TEST mode: cancel subscriptions and delete customers for these realms.`,
    `       Search customers by email pattern: ${m.emailPattern}`,
    ...(customers.length ? [`       customer ids: ${customers.join(", ")}`] : [`       (no customer ids captured; search by email)`]),
    ...(subs.length ? [`       subscription ids: ${subs.join(", ")}`] : []),
    `[ ] 3. Payer DB (staging payers): remove wallet/subscription rows for the customer ids above, if wanted.`,
    `[ ] 4. Tide accounts: ${created.length} created of ${attempted} attempted (ids start with lt-${m.runId}-).`,
    `       ORK/master user records have no delete path; reservations from failed attempts are left too.`,
    `       Deleting the realms removes the TideCloak side.`,
    `[ ] 5. Delete runs/${m.runId}/users.secret.json when the users are no longer needed.`,
  ];
  return lines.join("\n");
}

function stepTable(steps: StepSummary[]): string {
  const rows = ["| step | kind | op | target | arrivals | ok | fail | expected | dropped | err% | on-time% | p50 ms | p95 ms | queue p95 ms | cpu avg | verdict |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"];
  for (const s of steps) {
    for (const o of s.ops) {
      rows.push(`| ${s.step} | ${s.kind} | ${o.op} | ${fmtRate(o.targetRate)} | ${o.arrivals} | ${o.ok} | ${o.failed} | ${o.expected} | ${o.dropped} | ${(o.errorRate * 100).toFixed(1)} | ${(o.onTimeRatio * 100).toFixed(0)} | ${o.p50 ?? "-"} | ${o.p95 ?? "-"} | ${o.queueWaitP95 ?? "-"} | ${s.client.cpuAvg ?? "-"} | ${s.verdict} |`);
    }
  }
  return rows.join("\n");
}

export interface ReportInput {
  dir: string;
  runId: string;
  scenario: string;
  target: string;
  promJob: string;
  config: Record<string, unknown>;
  result: EngineResult;
  manifest: Manifest;
  watch?: { restarts: unknown; prom: unknown };
}

export function writeReport(r: ReportInput): { json: string; md: string } {
  const steps = r.result.steps;
  const start = steps[0]?.startedAt ?? new Date().toISOString();
  const end = steps[steps.length - 1]?.endedAt ?? new Date().toISOString();
  const pad = (iso: string, ms: number) => new Date(new Date(iso).getTime() + ms).toISOString();
  const winStart = pad(start, -60_000);
  const winEnd = pad(end, 60_000);
  const ceil = ceilings(steps);
  const sigTotals: Record<string, number> = {};
  const codeTotals: Record<string, number> = {};
  for (const s of steps) for (const o of s.ops) {
    for (const [k, v] of Object.entries(o.signatures)) sigTotals[k] = (sigTotals[k] ?? 0) + v;
    for (const [k, v] of Object.entries(o.codes)) codeTotals[k] = (codeTotals[k] ?? 0) + v;
  }
  const summary = {
    runId: r.runId, scenario: r.scenario, target: r.target, window: { start: winStart, end: winEnd },
    abortReason: r.result.abortReason, stopReason: r.result.stopReason, baselineP95: r.result.baselineP95,
    ceilings: ceil, signatures: sigTotals, codes: codeTotals, config: r.config, steps, watch: r.watch ?? null,
  };
  const json = join(r.dir, "summary.json");
  writeFileSync(json, JSON.stringify(summary, null, 2));

  const md = [
    `# Staging incident sim: ${r.scenario} (${r.runId})`,
    ``,
    `- target: ${r.target}`,
    `- window (UTC, padded 1 min): ${winStart} to ${winEnd}`,
    `- abort: ${r.result.abortReason ?? "none"}`,
    `- stop: ${r.result.stopReason ?? "none"}`,
    ``,
    `## Ceilings (target rate per op)`,
    ``,
    `| op | last ok | knee | break | client-bound |`,
    `|---|---|---|---|---|`,
    ...ceil.map((c) => `| ${c.op} | ${c.lastOk !== null ? fmtRate(c.lastOk) : "-"} | ${c.knee !== null ? fmtRate(c.knee) : "-"} | ${c.brk !== null ? fmtRate(c.brk) : "-"} | ${c.clientBound !== null ? fmtRate(c.clientBound) : "-"} |`),
    ``,
    `A client-bound step means the load machine, not staging, was the limit at that rate.`,
    ``,
    `## Steps`,
    ``,
    stepTable(steps),
    ``,
    `## Step reasons`,
    ``,
    ...steps.map((s) => `- step ${s.step} (${s.startedAt} to ${s.endedAt}): ${s.verdict}${s.flags.reasons.length ? ": " + s.flags.reasons.join("; ") : ""}`),
    ``,
    `## Failure signatures seen`,
    ``,
    ...(Object.keys(sigTotals).length ? Object.entries(sigTotals).map(([k, v]) => `- ${k}: ${v} (${SIGNATURES.find((s) => s.id === k)?.note ?? ""})`) : ["- none"]),
    ``,
    `## Error codes`,
    ``,
    ...(Object.keys(codeTotals).length ? Object.entries(codeTotals).map(([k, v]) => `- ${k}: ${v}`) : ["- none"]),
    ``,
    `## Server side, for this window`,
    ``,
    "```kusto",
    kql(winStart, winEnd),
    "```",
    ``,
    `Prometheus (job ${r.promJob}):`,
    ``,
    "```promql",
    ...promql(r.promJob),
    "```",
    ``,
    `## Cleanup`,
    ``,
    "```",
    cleanupChecklist(r.manifest, join(r.dir, "manifest.json")),
    "```",
  ].join("\n");
  const mdPath = join(r.dir, "summary.md");
  writeFileSync(mdPath, md);
  return { json, md: mdPath };
}
