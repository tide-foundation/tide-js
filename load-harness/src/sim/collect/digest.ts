// Plain-English digest for the top of summary.md: the result, causes ranked with a small built-in
// dictionary, the persistent-failure check and condensed server health. Raw tables stay in the appendix.

import type { StepSummary } from "../engine.js";
import type { BrowserUsage } from "../remote.js";
import type { Inventory, StepServer } from "./collectors.js";
import { fmtRate } from "../util.js";
import { DEFAULT_THRESHOLDS } from "../engine.js";
import { isSoftSignature } from "../signatures.js";

export interface CauseInfo {
  title: string;
  explain: string;
  action: string;
  weight: number;          // prior: how likely this is to break a run on its own
  noiseUnless?: string;    // noise unless this other signature also shows up
  expected?: string;       // an expected test limit, not a staging failure; text for the result line
}

export const CAUSES: Record<string, CauseInfo> = {
  licence_active_cap: {
    title: "Test realm hit its licence active-user cap",
    explain: "The payer refused new users once the realm reached its monthly active-user cap (MaxConcurrentAccountsPerMonth); ORKs pass the refusal back on Convert, so sign-ups stall. This is a limit of the test licence, not a staging failure.",
    action: "Raise MaxConcurrentAccountsPerMonth on the load-test subscription (or spread users over more realms) and re-run.",
    weight: 20,
    expected: "stopped by licence cap",
  },
  seat_cap: {
    title: "Test realm hit its seat cap",
    explain: "The realm reached its total user count, so new users were refused. This is a pool sizing limit, not a staging failure.",
    action: "Use more realms (prepare-realms) or raise the seat count, then re-run.",
    weight: 20,
    expected: "stopped by realm seat cap",
  },
  oidc_param_too_long: {
    title: "TideCloak ignored an oversized refresh token",
    explain: "TideCloak drops OIDC parameters longer than 4000 characters, so the admin's refresh_token was ignored and the refresh failed. The token grows with every realm the admin manages, so this depends on how many realms exist, not on the request rate.",
    action: "Keep the admin token under the limit (fewer realm roles in it, or a lightweight token) or raise TideCloak's OIDC parameter limit, then re-run with a fresh admin.",
    weight: 9,
  },
  header_too_large: {
    title: "Requests refused with 431 (headers too large)",
    explain: "The access token plus the other headers went over TideCloak's 64 KB header limit, so admin requests were refused before reaching Keycloak.",
    action: "Shrink the admin access token (fewer realm roles in it) or raise the HTTP header limit.",
    weight: 9,
  },
  restarts: {
    title: "Container restarted or crashed",
    explain: "A container restarted during the step; in-flight requests on it fail and state held in memory is lost.",
    action: "Read that container's logs and exit code around the restart time.",
    weight: 8,
  },
  sqlite_locked: {
    title: "ORK SQLite store locked",
    explain: "The ORK authenticator keeps its SQLite file on an SMB share; concurrent writes hit the lock and fail.",
    action: "Move the ORK SQLite store off the SMB share, or serialize its writes.",
    weight: 7,
  },
  sqlite_malformed: {
    title: "ORK SQLite file damaged",
    explain: "SQLite reported a malformed database, usually after an interrupted write on the SMB share.",
    action: "Restore or rebuild the ORK SQLite file and check the share.",
    weight: 7,
  },
  add_user_failed: {
    title: "Master ORK failed to add a user",
    explain: "The master logged a real SubmitUser failure, so a sign-up did not complete on the master.",
    action: "Read the master logs around the first failure; check master-libs PR #30.",
    weight: 7,
  },
  uid_missing: {
    title: "Master ORK could not find a UID",
    explain: "An ORK asked the master for a UID that was not there yet (SubmitUser lag).",
    action: "Check master SubmitUser latency and Postgres at that time.",
    weight: 6,
  },
  vendor_already_created: {
    title: "Payer refused the vendor (already created)",
    explain: "The payer saw a vendor that was half set up by an earlier attempt and refused to create it again.",
    action: "Clean the partial vendor and check why the first attempt stopped.",
    weight: 6,
  },
  vendor_keygen_failed: {
    title: "Vendor key setup failed",
    explain: "VVK setup failed after the wallet commit.",
    action: "Read the payer and ORK logs around the failure.",
    weight: 6,
  },
  stmt_timeout: {
    title: "Postgres statement timeout",
    explain: "A query ran past Postgres statement_timeout and was cancelled.",
    action: "Look for slow queries and lock waits on Postgres at that time.",
    weight: 5,
  },
  npgsql_timeout: {
    title: "ORK timed out talking to Postgres",
    explain: "Npgsql timed out (connection or command), usually a busy or exhausted Postgres.",
    action: "Check Postgres connections and CPU at that time.",
    weight: 5,
  },
  unhandled_exception: {
    title: "Unhandled exception",
    explain: "A service logged an unhandled exception.",
    action: "Read the stack trace in the logs (see How to dig deeper).",
    weight: 4,
  },
  gateway: {
    title: "Gateway or upstream error (502/503/504)",
    explain: "A request got a gateway error, e.g. the Tide signing network could not complete it. Usually transient; it only matters when it repeats.",
    action: "Check whether it repeats across steps; read TideCloak and ORK logs at that time.",
    weight: 5,
  },
  high_cpu: {
    title: "Container CPU at or above 90%",
    explain: "A component ran at or above 90% of its CPU limit in a failing step, so it was close to saturated.",
    action: "Give it more CPU or replicas, or spread the load, then re-run.",
    weight: 4,
  },
  uid_duplicate: {
    title: "Master ORK concurrent UID insert",
    explain: "Concurrent SubmitUser calls insert the same UID on the master; the code catches the duplicate (master-libs PR #30). Usually harmless.",
    action: "Nothing for this run; master-libs PR #30 removes the log noise.",
    weight: 2,
    noiseUnless: "add_user_failed",
  },
  pg_unique_violation: {
    title: "Postgres unique constraint violation",
    explain: "Postgres refused a duplicate row. On the master ORK this is the same caught concurrent insert as uid_duplicate.",
    action: "Nothing unless it shows up on another table or with real failures.",
    weight: 2,
    noiseUnless: "add_user_failed",
  },
};

// Client error-text signatures that map onto a dictionary entry.
const CLIENT_TO_CAUSE: Record<string, string> = {
  SQLITE_LOCKED: "sqlite_locked", STATEMENT_TIMEOUT: "stmt_timeout", UID_NOT_FOUND: "uid_missing",
  VENDOR_ALREADY_CREATED: "vendor_already_created", VENDOR_KEYGEN_FAILED: "vendor_keygen_failed",
  LICENCE_ACTIVE_CAP: "licence_active_cap", SEAT_CAP: "seat_cap", GATEWAY: "gateway", UID_DUPLICATE: "uid_duplicate", PG_UNIQUE_VIOLATION: "pg_unique_violation", HEADER_TOO_LARGE: "header_too_large",
};

export type CauseStatus = "expected limit" | "likely cause" | "possible contributor" | "noise";

export interface Cause extends CauseInfo {
  id: string;
  status: CauseStatus;
  count: number;
  apps: string[];
  steps: number[];
  firstSeen: string | null;
  score: number;
  lead?: boolean;          // the one the At a glance block names
}

const stepRate = (s: StepSummary) => Math.max(0, ...s.ops.map((o) => o.targetRate));
const stepOk = (s: StepSummary) => s.ops.reduce((a, o) => a + o.ok, 0);
const stepFailed = (s: StepSummary) => s.ops.reduce((a, o) => a + o.failed, 0);
const stepErr = (s: StepSummary) => { const n = stepOk(s) + stepFailed(s); return n ? stepFailed(s) / n : 0; };
const hhmmss = (iso: string | null | undefined) => (iso ? iso.replace(/^.*T(\d\d:\d\d:\d\d).*$/, "$1Z") : "-");

export interface Persistent { step: StepSummary; breakStep: StepSummary }

// A later step at the same or lower rate failing at least as badly as the break step points at
// state or size, not throughput.
export function persistentFailure(steps: StepSummary[]): Persistent | null {
  const i = steps.findIndex((s) => s.verdict === "break");
  if (i < 0) return null;
  const b = steps[i];
  const s = steps.slice(i + 1).find((x) => stepOk(x) + stepFailed(x) > 0 && stepRate(x) <= stepRate(b) && stepErr(x) >= stepErr(b));
  return s ? { step: s, breakStep: b } : null;
}

export function rankCauses(steps: StepSummary[], server: StepServer[]): Cause[] {
  const acc = new Map<string, { count: number; apps: Set<string>; steps: Set<number>; first: string | null }>();
  const hit = (id: string, n: number, app: string, step: number, at: string | null) => {
    const a = acc.get(id) ?? { count: 0, apps: new Set(), steps: new Set(), first: null };
    a.count += n; a.apps.add(app); a.steps.add(step);
    if (at && (!a.first || at < a.first)) a.first = at;
    acc.set(id, a);
  };
  for (const sv of server) {
    for (const [app, sigs] of Object.entries(sv.logs?.signatures ?? {})) {
      for (const [k, n] of Object.entries(sigs)) if (n && CAUSES[k]) hit(k, n, app, sv.step, sv.logs?.firstSeen?.[app]?.[k] ?? null);
    }
    for (const [app, m] of Object.entries(sv.apps)) if ((m.restarts ?? 0) > 0) hit("restarts", m.restarts!, app, sv.step, null);
    for (const e of sv.logs?.system ?? []) if (/Terminated|BackOff|Crashing/i.test(e.reason)) hit("restarts", e.n, e.app, sv.step, null);
  }
  for (const s of steps) for (const o of s.ops) for (const [k, n] of Object.entries(o.signatures)) if (CLIENT_TO_CAUSE[k]) hit(CLIENT_TO_CAUSE[k], n, "client", s.step, null);

  // A component at 90%+ CPU in a failing step is a contributor.
  const failing = new Set(steps.filter((s) => stepFailed(s) > 0).map((s) => s.step));
  for (const sv of server.filter((x) => failing.has(x.step))) {
    for (const [app, m] of Object.entries(sv.apps)) if ((m.cpuPctMax ?? 0) >= 90) hit("high_cpu", 1, `${app} ${m.cpuPctMax}%`, sv.step, null);
    if ((sv.pg?.cpuPctMax ?? 0) >= 90) hit("high_cpu", 1, `Postgres ${sv.pg!.cpuPctMax}%`, sv.step, null);
  }
  const pers = persistentFailure(steps);
  // At a low error rate a soft signature or busy CPU explains little, so it stays a contributor.
  const lowErr = lowErrorRate(steps);
  const out: Cause[] = [...acc].map(([id, a]) => {
    const info = CAUSES[id];
    const noise = !!info.noiseUnless && !acc.has(info.noiseUnless);
    const inFailing = [...a.steps].some((s) => failing.has(s));
    const score = info.expected ? 100 + info.weight : noise ? info.weight - 10 : info.weight + (inFailing ? 5 : 0) + (pers && a.steps.has(pers.step.step) ? 10 : 0);
    return { id, ...info, status: info.expected ? "expected limit" : noise ? "noise" : "possible contributor", count: a.count, apps: [...a.apps].sort(), steps: [...a.steps].sort((x, y) => x - y), firstSeen: a.first, score } as Cause;
  }).sort((x, y) => y.score - x.score || y.count - x.count);
  const top = out.find((c) => c.status !== "noise" && c.steps.some((s) => failing.has(s)) && c.id !== "high_cpu" && !(lowErr && isSoftSignature(c.id)));
  if (top) { top.lead = true; if (!top.expected) top.status = "likely cause"; }
  return out;
}

const lowErrorRate = (steps: StepSummary[]) => steps.filter((s) => stepFailed(s) > 0).every((s) => stepErr(s) <= DEFAULT_THRESHOLDS.breakErrorRate);

// Verdict with soft-signature warnings, e.g. "ok (warnings: GATEWAY x1)".
export function verdictText(s: StepSummary): string {
  const w = Object.entries(s.flags.warnings ?? {});
  return `${s.verdict}${w.length ? ` (warnings: ${w.map(([k, n]) => `${k} x${n}`).join(", ")})` : ""}`;
}

// A break caused only by failure signatures while the error rate stayed under the threshold.
export function signatureOnlyBreak(s: StepSummary): string | null {
  if (!s.flags.breakSignatures.length || stepErr(s) > DEFAULT_THRESHOLDS.breakErrorRate) return null;
  const n = s.ops.reduce((a, o) => a + s.flags.breakSignatures.reduce((b, k) => b + (o.signatures[k] ?? 0), 0), 0);
  const what = s.flags.breakSignatures.map((k) => k.toLowerCase().replace(/_/g, " ")).join("/");
  const soft = s.flags.breakSignatures.every(isSoftSignature);
  return `broke on ${n} ${what} error${n === 1 ? "" : "s"} (${(stepErr(s) * 100).toFixed(0)}%)${soft ? " under strict rules; the current rule only warns on it" : ", a hard signature"}`;
}

export function resultLabel(steps: StepSummary[], abortReason: string | null): string {
  if (abortReason) return "ABORT";
  if (steps.some((s) => s.verdict === "break")) return "BREAK";
  if (steps.some((s) => s.verdict === "client-bound")) return "CLIENT-BOUND";
  if (steps.some((s) => s.verdict === "knee")) return "KNEE";
  return "PASS";
}

function confidence(top: Cause | undefined, steps: StepSummary[], pers: Persistent | null): string {
  const failing = steps.filter((s) => stepFailed(s) > 0).map((s) => s.step);
  if (!failing.length) return "n/a (no failures)";
  if (!top) return "low (no server signature lines up with the failures)";
  const all = failing.every((s) => top.steps.includes(s));
  if (all && top.count >= 5 && (!pers || top.steps.includes(pers.step.step))) return `high (${top.id} is in every failing step${pers ? ", including the one after load dropped" : ""})`;
  return `medium (${top.id} is in ${top.steps.filter((s) => failing.includes(s)).length} of ${failing.length} failing steps)`;
}

const causeEvidence = (c: Cause) => `${c.apps.join(", ")}: ${c.id} x${c.count}, step${c.steps.length > 1 ? "s" : ""} ${c.steps.join(",")}${c.firstSeen ? `, first seen ${hhmmss(c.firstSeen)}` : ""}`;

export interface DigestInput {
  steps: StepSummary[];
  server: StepServer[];
  abortReason: string | null;
  browser?: BrowserUsage;
  realmTimes?: string[];   // createdAt of every run realm, to place a first-seen time in the run
}

export function atAGlance(d: DigestInput, causes: Cause[]): string[] {
  const { steps } = d;
  const lines = ["## At a glance", ""];
  if (!steps.length) return [...lines, "- no load steps in this run (server-only run)", ""];
  const label = resultLabel(steps, d.abortReason);
  const brk = steps.find((s) => s.verdict === "break" || s.verdict === "aborted");
  const sigOnly = brk ? signatureOnlyBreak(brk) : null;
  const top = causes.find((c) => c.lead);
  lines.push(`- **Result: ${label}${top?.expected ? `, ${top.expected} (an expected test limit, not a staging failure)` : ""}**${brk ? ` at step ${brk.step} (${fmtRate(stepRate(brk))}): ${stepFailed(brk)} of ${stepOk(brk) + stepFailed(brk)} failed (${(stepErr(brk) * 100).toFixed(0)}%)` : ""}${brk?.flags.reasons.length ? `; trigger: ${brk.flags.reasons.join("; ")}` : ""}${d.abortReason ? `; abort: ${d.abortReason}` : ""}${sigOnly ? `; ${sigOnly}` : ""}`);
  const clean = steps.filter((s) => s.kind !== "confirm" && stepFailed(s) === 0 && stepOk(s) > 0);
  const best = clean.length ? clean.reduce((a, b) => (stepRate(b) > stepRate(a) ? b : a)) : null;
  lines.push(`- **Worked fully up to:** ${best ? `${fmtRate(stepRate(best))} (step ${best.step}, ${stepOk(best)} of ${stepOk(best)} ok)` : "no step completed without failures"}${brk ? `; broke at ${fmtRate(stepRate(brk))} (step ${brk.step})` : ""}`);
  lines.push(`- **Most likely cause:** ${top ? `${top.title} (${causeEvidence(top)}${placeInRun(top.firstSeen, d.realmTimes)})` : sigOnly ? "none stands out; the break was signature-only at a low error rate, contributors are under Likely causes" : "none found in the server evidence"}`);
  const pers = persistentFailure(steps);
  if (pers) lines.push(`- **Failures continued after load dropped:** step ${pers.step.step} at ${fmtRate(stepRate(pers.step))} failed ${(stepErr(pers.step) * 100).toFixed(0)}% vs ${(stepErr(pers.breakStep) * 100).toFixed(0)}% at the break: likely a state or size problem, not throughput`);
  lines.push(`- **Load machine or Playwright the limit:** ${clientLimit(steps, d.browser)}`);
  const noise = causes.filter((c) => c.status === "noise");
  if (noise.length) lines.push(`- **Noise, not the cause:** ${noise.map((c) => `${c.id} x${c.count} (${c.apps.join(", ")})`).join(", ")}${noise.some((c) => c.noiseUnless) ? ": caught by the code, no add_user_failed lines" : ""}`);
  lines.push(`- **Confidence:** ${!top && sigOnly ? "low (a signature-only break at a low error rate is not enough evidence for a cause)" : confidence(top, steps, pers)}`);
  lines.push(`- **Next action:** ${top ? top.action : sigOnly ? "re-run with the default (non-strict) signature rule so soft errors only warn and the ramp continues" : label === "PASS" ? "raise --max-steps or the start rate to find the knee" : "read the Appendix tables and the logs (How to dig deeper); no known signature explains this"}`);
  const missing = d.server.reduce((a, s) => a + s.missing.length, 0);
  if (missing) lines.push(`- **Missing server data:** ${missing} item(s), listed per step in the Appendix`);
  lines.push("");
  return lines;
}

function placeInRun(first: string | null, realmTimes?: string[]): string {
  if (!first || !realmTimes?.length) return "";
  const n = realmTimes.filter((t) => t <= first).length;
  return n ? `, when this run had created ${n} realm(s)` : "";
}

export function clientLimit(steps: StepSummary[], browser?: BrowserUsage): string {
  const cpu = Math.max(0, ...steps.map((s) => s.client.cpuMax ?? 0));
  const dropped = steps.reduce((a, s) => a + s.ops.reduce((b, o) => b + o.dropped, 0), 0);
  const queue = Math.max(0, ...steps.flatMap((s) => s.ops.map((o) => o.queueWaitP95 ?? 0)));
  const bound = steps.filter((s) => s.flags.clientBound);
  const failedBrowsers = browser?.sessions.filter((s) => s.error).length ?? 0;
  const conn = browser && browser.endpoint !== "local" ? `, ${browser.sessions.length - failedBrowsers} of ${browser.sessions.length} remote browsers connected` : "";
  const nums = `client CPU max ${cpu}%, ${dropped} dropped, queue wait p95 max ${queue}ms${conn}`;
  // Failing operations hold their browser context until timeout, which grows the queue on its own.
  const inflated = bound.length && !failedBrowsers && cpu < 80 && dropped === 0 && bound.every((s) => stepErr(s) >= 0.2);
  if (inflated) return `no (queue wait inflated by failing ${[...new Set(bound.flatMap((s) => s.ops.filter((o) => o.failed).map((o) => o.op)))].join("/")} operations holding browser slots until timeout; ${nums})`;
  return `${bound.length || failedBrowsers ? "YES" : "no"} (${nums})`;
}

export function stepsDigest(steps: StepSummary[], server: StepServer[], causes: Cause[]): string[] {
  const lines = ["## What happened, step by step", ""];
  if (!steps.length) return [...lines, "- no load steps", ""];
  lines.push("| step | kind | rate | started | ok | failed | p95 s | verdict |", "|---|---|---|---|---|---|---|---|");
  for (const s of steps) {
    const p95 = Math.max(0, ...s.ops.map((o) => o.p95 ?? 0));
    lines.push(`| ${s.step} | ${s.kind} | ${fmtRate(stepRate(s))} | ${hhmmss(s.startedAt)} | ${stepOk(s)} | ${stepFailed(s)} | ${p95 ? (p95 / 1000).toFixed(1) : "-"} | ${verdictText(s).replace(/^\w+/, (v) => v.toUpperCase())} |`);
  }
  lines.push("");
  const noise = new Set(causes.filter((c) => c.status === "noise").map((c) => c.id));
  const pers = persistentFailure(steps);
  for (const s of steps) {
    const codes = Object.entries(s.ops.reduce((a, o) => { for (const [k, v] of Object.entries(o.codes)) a[k] = (a[k] ?? 0) + v; return a; }, {} as Record<string, number>));
    const sv = server.find((x) => x.step === s.step);
    const sigs = Object.entries(sv?.logs?.signatures ?? {}).flatMap(([app, m]) => Object.entries(m).filter(([k, v]) => v > 0 && CAUSES[k] && !noise.has(k)).map(([k, v]) => `${app} ${k} x${v}${sv?.logs?.firstSeen?.[app]?.[k] ? ` from ${hhmmss(sv.logs.firstSeen[app][k])}` : ""}`));
    const why = s.flags.reasons.length ? ` because ${s.flags.reasons.join("; ")}` : "";
    lines.push(`- **Step ${s.step}** (${s.kind}, ${fmtRate(stepRate(s))}): ${stepOk(s)} ok, ${stepFailed(s)} failed${codes.length ? ` (${codes.map(([k, v]) => `${k} x${v}`).join(", ")})` : ""}. ${s.verdict.toUpperCase()}${why}. Server: ${sigs.length ? sigs.join(", ") : "no failure signatures"}.${pers?.step.step === s.step ? " Load was lower than at the break, yet it failed as much or more." : ""}`);
  }
  if (pers) {
    const from = pers.breakStep.startedAt;
    const to = pers.step.endedAt;
    const fresh = causes.filter((c) => c.status !== "noise" && c.firstSeen && c.firstSeen >= from && c.firstSeen <= to);
    lines.push("", `**Failures continued after load dropped: likely a state or size problem, not throughput.** First seen between the break and step ${pers.step.step}: ${fresh.length ? fresh.map((c) => `${c.id} at ${hhmmss(c.firstSeen)} (${c.apps.join(", ")})`).join(", ") : "no new signature; check the Appendix logs"}.`);
  }
  lines.push("");
  return lines;
}

export function causesMarkdown(causes: Cause[]): string[] {
  const lines = ["## Likely causes, ranked", ""];
  if (!causes.length) return [...lines, "- no known failure signature in the server logs or client errors", ""];
  causes.forEach((c, i) => {
    lines.push(`${i + 1}. **${c.title}** (\`${c.id}\`): **${c.status}**`);
    lines.push(`   - what it means: ${c.explain}`);
    lines.push(`   - evidence: ${causeEvidence(c)}${c.status === "noise" && c.noiseUnless ? `; no ${c.noiseUnless} lines, so the errors were caught` : ""}`);
    lines.push(`   - what to do: ${c.action}`);
  });
  lines.push("");
  return lines;
}

export function healthMarkdown(server: StepServer[], inv: Inventory | null, causes: Cause[]): string[] {
  const lines = ["## Server health per step", ""];
  if (!server.length) return [...lines, "- not collected (use --collect auto, or report --run <id> --recollect)", ""];
  const noise = new Set(causes.filter((c) => c.status === "noise").map((c) => c.id));
  for (const s of server) {
    lines.push(`**Step ${s.step}** (${hhmmss(s.window.start)} to ${hhmmss(s.window.end)})`, "");
    for (const [app, m] of Object.entries(s.apps).sort()) {
      const sig = s.logs?.signatures[app] ?? {};
      const top = Object.entries(sig).filter(([k, v]) => k !== "error_lines" && v > 0).sort((a, b) => b[1] - a[1])[0];
      const role = inv?.apps.find((a) => a.name === app)?.role;
      lines.push(`- ${app}${role ? ` (${role})` : ""}: CPU max ${m.cpuPctMax ?? "-"}%, memory max ${m.memPctMax ?? "-"}%, restarts ${m.restarts ?? "-"}, error lines ${sig.error_lines ?? (s.logs ? 0 : "-")}, top signature ${top ? `${top[0]} x${top[1]}${noise.has(top[0]) ? " (noise)" : ""}` : "none"}`);
    }
    const p = s.pg;
    lines.push(`- Postgres: ${p ? `CPU max ${p.cpuPctMax ?? "-"}%, memory max ${p.memPctMax ?? "-"}%, connections max ${p.activeConnMax ?? "-"} of ${p.maxConnections ?? "-"}, IOPS max ${p.iopsPctMax ?? "-"}%, credits min ${p.cpuCreditsMin ?? "-"}, failed connections ${p.connectionsFailed ?? "-"}` : "not collected"}`);
    if (s.missing.length) lines.push(`- missing: ${s.missing.length} item(s), see Appendix`);
    lines.push("");
  }
  return lines;
}
