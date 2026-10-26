// Summary report (JSON + Markdown), the server-side queries for the run window, and the manual cleanup checklist.

import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { EngineResult, StepSummary } from "./engine.js";
import type { Manifest } from "./sink.js";
import { fmtRate } from "./util.js";
import { SIGNATURES } from "./signatures.js";
import { AZURE_PRICE_PER_MIN, type BrowserUsage } from "./remote.js";
import type { StepServer } from "./collect/collectors.js";
import type { ServerMeta } from "./collect/index.js";
import { analyse, analysisMarkdown } from "./collect/analysis.js";
import { metadataMarkdown, phaseMarkdown, serverMarkdown, serverSignatureLines } from "./collect/render.js";

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
    "            uid_duplicate=countif(Log_s has \"IX_UIDs_Id\"),",
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

// Token alg per op, read back from events.jsonl. RS256 means the token was signed locally, so no
// Tide signing (PreSign) happened for it.
export function algCounts(eventsPath: string): Record<string, Record<string, number>> {
  const out: Record<string, Record<string, number>> = {};
  if (!existsSync(eventsPath)) return out;
  for (const line of readFileSync(eventsPath, "utf8").split("\n")) {
    if (!line) continue;
    const e = JSON.parse(line) as { op: string; ok: boolean; extra?: { alg?: string } };
    if (!e.ok || !e.extra?.alg) continue;
    out[e.op] ??= {};
    out[e.op][e.extra.alg] = (out[e.op][e.extra.alg] ?? 0) + 1;
  }
  return out;
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
  browserUsage?: BrowserUsage;
  server?: StepServer[];
  serverMeta?: ServerMeta | null;
  window?: { start: string; end: string };   // for runs without steps (prepare-realms)
}

export function browserSection(u: BrowserUsage | undefined): string[] {
  if (!u) return ["- no browsers used"];
  if (u.endpoint === "local") return ["- endpoint: local Chromium"];
  return [
    `- endpoint: Azure Playwright workspace`,
    `- remote browsers: ${u.remoteBrowsers} (${u.contextsPerBrowser ?? "-"} contexts each)`,
    `- remote browser-minutes: ${u.browserMinutes.toFixed(2)} (est. $${u.estCostUsd.toFixed(3)} at $${AZURE_PRICE_PER_MIN}/min)`,
    ...u.sessions.map((s) => `- browser ${s.index}: ${s.error ? "connect FAILED: " + s.error : `connect ${s.connectMs}ms, open ${s.openedAt !== null ? (((s.closedAt ?? Date.now()) - s.openedAt) / 60_000).toFixed(2) : "0"} min`}`),
  ];
}

// Client signatures (from error text) plus server log signatures per step.
export function failureSignatureLines(sigTotals: Record<string, number>, server: StepServer[]): string[] {
  const client = Object.entries(sigTotals).map(([k, v]) => `- client ${k}: ${v} (${SIGNATURES.find((s) => s.id === k)?.note ?? ""})`);
  const all = [...client, ...serverSignatureLines(server)];
  return all.length ? all : ["- none"];
}

export function writeReport(r: ReportInput): { json: string; md: string } {
  const steps = r.result.steps;
  const start = steps[0]?.startedAt ?? r.window?.start ?? new Date().toISOString();
  const end = steps[steps.length - 1]?.endedAt ?? r.window?.end ?? new Date().toISOString();
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
  const algs = algCounts(join(r.dir, "events.jsonl"));
  const server = r.server ?? [];
  const inv = r.serverMeta?.start ?? r.serverMeta?.end ?? null;
  const analysis = analyse(steps, server, inv);
  const localSigned = Object.values(algs).some((m) => Object.keys(m).some((a) => a !== "EdDSA"));
  const summary = {
    algs,
    runId: r.runId, scenario: r.scenario, target: r.target, window: { start: winStart, end: winEnd },
    abortReason: r.result.abortReason, stopReason: r.result.stopReason, baselineP95: r.result.baselineP95,
    browser: r.browserUsage ?? null,
    analysis,
    serverCollected: server.length > 0,
    serverMissing: server.flatMap((x) => x.missing.map((m) => `step ${x.step}: ${m}`)),
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
    ...analysisMarkdown(analysis),
    `## Browsers`,
    ``,
    ...browserSection(r.browserUsage),
    ``,
    `## Token signing`,
    ``,
    ...(Object.keys(algs).length ? Object.entries(algs).map(([op, m]) => `- ${op}: ${Object.entries(m).map(([a, n]) => `${a} x${n}`).join(", ")}`) : ["- no tokens minted"]),
    ...(localSigned ? [``, `WARNING: some tokens were not EdDSA, so those operations did not go through Tide signing (Key.PreSign). TideCloak only signs through the Tide network on realms with IGA on and EdDSA as the default algorithm; use prepare-realms (default --tide-full) realms, or check the realm if it should already be Tide-signed.`] : []),
    ``,
    `## Steps`,
    ``,
    stepTable(steps),
    ``,
    ...phaseMarkdown(steps),
    `## Step reasons`,
    ``,
    ...steps.map((s) => `- step ${s.step} (${s.startedAt} to ${s.endedAt}): ${s.verdict}${s.flags.reasons.length ? ": " + s.flags.reasons.join("; ") : ""}`),
    ``,
    `## Failure signatures seen`,
    ``,
    ...failureSignatureLines(sigTotals, server),
    ``,
    `## Error codes`,
    ``,
    ...(Object.keys(codeTotals).length ? Object.entries(codeTotals).map(([k, v]) => `- ${k}: ${v}`) : ["- none"]),
    ``,
    ...serverMarkdown(server, inv),
    ...metadataMarkdown(r.serverMeta ?? null),
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
