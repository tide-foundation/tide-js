// Unit tests for the simulator's pure logic and the engine loop. No network.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseRate, parseDuration, scrub } from "../util.js";
import { resolveTarget, assertAllowedUrl, isAllowedHost } from "../targets.js";
import { planSteps, judgeStep, summariseOp, Engine, DEFAULT_THRESHOLDS, nextGapMs, type EventRow, type OpSpec } from "../engine.js";
import { matchSignatures, isBreakSignature } from "../signatures.js";
import { RealmPool, LoginUserPool } from "../scenarios/browser.js";
import { errorCode, setupNames } from "../scenarios/setup.js";
import { Pool } from "../pool.js";
import { ClientMonitor } from "../monitor.js";
import { Jsonl } from "../sink.js";
import { ceilings, cleanupChecklist } from "../report.js";

test("rates and durations", () => {
  assert.equal(parseRate("2/min"), 2);
  assert.equal(parseRate("0.5/s"), 30);
  assert.equal(parseRate("120/h"), 2);
  assert.equal(parseRate("3"), 3);
  assert.throws(() => parseRate("fast"));
  assert.equal(parseDuration("5m"), 300_000);
  assert.equal(parseDuration("90s"), 90_000);
  assert.equal(parseDuration("250ms"), 250);
});

test("allowlist refuses production and unknown hosts", () => {
  assert.throws(() => resolveTarget("prod"));
  assert.throws(() => resolveTarget("staging", "https://login.dauth.me"), /production/);
  assert.throws(() => assertAllowedUrl("staging", "https://ork1.tideprotocol.com"), /production/);
  assert.throws(() => assertAllowedUrl("staging", "https://example.com"), /allowlist/);
  assert.throws(() => assertAllowedUrl("local", "https://staging.dauth.me"), /allowlist/);
  assert.equal(isAllowedHost("staging", "sork3.tideprotocol.com"), true);
  assert.equal(isAllowedHost("staging", "ork3.tideprotocol.com"), false);
  assert.equal(resolveTarget("staging").tcBase, "https://staging.dauth.me");
  assert.equal(resolveTarget("local").tcBase, "http://localhost:8080");
});

test("step plan doubles until max", () => {
  const s = planSteps({ startRate: 2, factor: 2, add: 0, maxRate: 20, maxSteps: 10, stepMs: 1, cooldownMs: 0 });
  assert.deepEqual(s.map((x) => x.baseRate), [2, 4, 8, 16]);
  const a = planSteps({ startRate: 1, factor: 2, add: 1, maxRate: 100, maxSteps: 3, stepMs: 1, cooldownMs: 0 });
  assert.deepEqual(a.map((x) => x.baseRate), [1, 2, 3]);
});

test("poisson gaps average to the rate", () => {
  let sum = 0;
  for (let i = 0; i < 20000; i++) sum += nextGapMs(60, "poisson");
  const mean = sum / 20000;
  assert.ok(mean > 900 && mean < 1100, `mean gap ${mean}`);
  assert.equal(nextGapMs(60, "uniform"), 1000);
});

function row(p: Partial<EventRow>): EventRow {
  return { ts: "", runId: "r", scenario: "s", op: "x", step: 1, stepKind: "ramp", targetRate: 1, seq: 1, ok: true, code: null,
    signatures: [], expected: false, dropped: false, late: false, queueWaitMs: 0, latencyMs: 100, phases: {}, ...p };
}

test("summary excludes expected outcomes from the error rate", () => {
  const rows = [row({}), row({}), row({ ok: false, code: "SEAT_CAP", expected: true, signatures: ["SEAT_CAP"] }), row({ ok: false, code: "E" }), row({ dropped: true, ok: false })];
  const s = summariseOp(rows, "x", 1, 60_000);
  assert.equal(s.ok, 2);
  assert.equal(s.failed, 1);
  assert.equal(s.expected, 1);
  assert.equal(s.dropped, 1);
  assert.ok(Math.abs(s.errorRate - 1 / 3) < 1e-9);
});

test("judge: knee, break, client-bound", () => {
  const client = { cpuAvg: 20, cpuMax: 30, loopLagP95: 5, maxQueue: {}, poolBusyAvg: {} };
  const ok = summariseOp([row({ latencyMs: 100 }), row({ latencyMs: 120 }), row({ latencyMs: 110 })], "x", 1, 60_000);
  assert.deepEqual(judgeStep([ok], client, { x: 100 }, DEFAULT_THRESHOLDS).reasons, []);
  const slow = summariseOp([row({ latencyMs: 500 }), row({ latencyMs: 600 }), row({ latencyMs: 550 })], "x", 1, 60_000);
  assert.equal(judgeStep([slow], client, { x: 100 }, DEFAULT_THRESHOLDS).knee, true);
  const bad = summariseOp([row({}), row({ ok: false, code: "X", signatures: ["SQLITE_LOCKED"] })], "x", 1, 60_000);
  const f = judgeStep([bad], client, { x: 100 }, DEFAULT_THRESHOLDS);
  assert.equal(f.break, true);
  assert.deepEqual(f.breakSignatures, ["SQLITE_LOCKED"]);
  const hot = judgeStep([ok], { ...client, cpuAvg: 95 }, { x: 100 }, DEFAULT_THRESHOLDS);
  assert.equal(hot.clientBound, true);
});

test("signatures", () => {
  assert.deepEqual(matchSignatures("Subscription sub_1 has exceeded its total user count.").map((s) => s.id), ["SEAT_CAP"]);
  assert.ok(matchSignatures("SQLite Error 5: 'database is locked'").some((s) => s.id === "SQLITE_LOCKED"));
  assert.ok(matchSignatures("TIDE-ORK-VOUCHER-VENDOR_ALREADY_CREATED").some((s) => s.id === "VENDOR_ALREADY_CREATED"));
  assert.equal(isBreakSignature("SEAT_CAP"), false);
  assert.equal(isBreakSignature("SQLITE_LOCKED"), true);
  const dup = matchSignatures('Npgsql.PostgresException (0x80004005): 23505: duplicate key value violates unique constraint "IX_UIDs_Id"').map((s) => s.id);
  assert.deepEqual(dup, ["UID_DUPLICATE", "PG_UNIQUE_VIOLATION"]);
  assert.ok(isBreakSignature("UID_DUPLICATE") && isBreakSignature("PG_UNIQUE_VIOLATION"));
});

test("server log signatures: uid_duplicate and pg_unique_violation", async () => {
  const { LOG_SIGNATURES, errorSamples } = await import("../collect/collectors.js");
  assert.match(LOG_SIGNATURES.uid_duplicate, /IX_UIDs_Id/);
  assert.match(LOG_SIGNATURES.pg_unique_violation, /23505/);
  // Log_s escapes the quotes, so the condition must not depend on them.
  assert.doesNotMatch(LOG_SIGNATURES.uid_duplicate, /\\"/);
  const ef = "An exception occurred in the database while saving changes for context type 'Ork.Shared.Helpers.NetworkDataContext'.\nMicrosoft.EntityFrameworkCore.DbUpdateException: An error occurred.\n ---> Npgsql.PostgresException (0x80004005): 23505: duplicate key value violates unique constraint \"IX_UIDs_Id\"\n\nDETAIL: Detail redacted";
  const s = errorSamples([
    { app: "sork2", msg: ef, n: 20 },
    { app: "sork2", msg: ef.replace("An error occurred.", "Other wrapper."), n: 1 },
    { app: "sork2", msg: "Failed executing DbCommand (Nms) [Parameters=[@p0='?']]\nINSERT INTO \"UIDs\"", n: 21 },
    { app: "sork2", msg: "Npgsql timeout Host=pg.example;Username=ork;Password=hunter2 token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc", n: 2 },
    { app: "sork2", msg: "rare", n: 1 },
  ]);
  assert.equal(s.sork2.length, 3);
  assert.deepEqual(s.sork2[0], { msg: 'Npgsql.PostgresException (0x80004005): 23505: duplicate key value violates unique constraint "IX_UIDs_Id"', n: 21 });
  assert.deepEqual(s.sork2[1], { msg: 'Failed executing DbCommand: INSERT INTO "UIDs"', n: 21 });
  assert.ok(s.sork2.every((x) => x.msg.length <= 160));
  const red = errorSamples([{ app: "a", msg: "Npgsql timeout Host=pg.example;Username=ork;Password=hunter2 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc " + "k".repeat(40), n: 1 }]).a[0].msg;
  assert.doesNotMatch(red, /hunter2|pg\.example|eyJ|kkkk/);
});

test("failure signatures merge client and server per step", async () => {
  const { failureSignatureLines } = await import("../report.js");
  const sv = (step: number, sigs: Record<string, Record<string, number>>) => ({ step, logs: { signatures: sigs, exec: [], system: [] } }) as unknown as import("../collect/collectors.js").StepServer;
  const server = [sv(1, { sork2: { error_lines: 10 } }), sv(2, { sork2: { uid_duplicate: 21, error_lines: 42 }, sork5: { stmt_timeout: 1 } })];
  assert.deepEqual(failureSignatureLines({}, server), ["- server step 2: sork2 uid_duplicate x21, sork5 stmt_timeout x1"]);
  assert.deepEqual(failureSignatureLines({}, []), ["- none"]);
  assert.match(failureSignatureLines({ SQLITE_LOCKED: 2 }, server)[0], /^- client SQLITE_LOCKED: 2/);
});

test("sign-up resolves on the captured callback without the page loading it", async () => {
  const { awaitCallback } = await import("../../admin/signupFlow.js");
  const stuck = { waitForURL: () => new Promise<void>(() => undefined), url: () => "chrome-error://chromewebdata/" };
  const cb = new URL("http://localhost:3000/callback?code=abc&state=s");
  assert.equal(await awaitCallback(stuck as never, "http://localhost:3000", 1000, Promise.resolve(cb)), cb.href);
  await assert.rejects(awaitCallback(stuck as never, "http://localhost:3000", 20, new Promise<URL>(() => undefined)), /callback not reached in 20ms/);
  // Without a captured callback it still waits on the page (provision path with a real server).
  const loaded = { waitForURL: async () => undefined, url: () => cb.href };
  assert.equal(await awaitCallback(loaded as never, "http://localhost:3000", 1000), cb.href);
});

test("new server signatures: oversized OIDC parameter, 431, failed add user", async () => {
  const { LOG_SIGNATURES, errorSamples } = await import("../collect/collectors.js");
  assert.match(LOG_SIGNATURES.oidc_param_too_long, /OIDC parameter.*longer.*than allowed/);
  assert.match(LOG_SIGNATURES.header_too_large, /Request Header Fields Too Large/);
  assert.match(LOG_SIGNATURES.add_user_failed, /Failed to add user/);
  assert.ok(matchSignatures("HTTP 431 Request Header Fields Too Large").some((s) => s.id === "HEADER_TOO_LARGE"));
  // TideCloak lines group once the timestamp, thread and token size are stripped.
  const line = (t: string, th: number, n: number) => `2026-10-26 ${t} WARN  [org.keycloak.protocol.oidc.endpoints.TokenEndpoint] (executor-thread-${th}) The size of OIDC parameter 'refresh_token' is longer (${n}) than allowed (4000). Ignoring the parameter.`;
  const s = errorSamples([{ app: "tc", msg: line("06:24:22,841", 47, 4012), n: 1 }, { app: "tc", msg: line("06:25:08,191", 46, 4094), n: 1 }]);
  assert.deepEqual(s.tc, [{ msg: "WARN [TokenEndpoint] The size of OIDC parameter 'refresh_token' is longer (N) than allowed (4000). Ignoring the parameter.", n: 2 }]);
});

function digestStep(step: number, kind: string, rate: number, ok: number, failed: number, verdict: string) {
  const s = fakeStep(step, verdict, 10_000);
  Object.assign(s, { kind, startedAt: `2026-10-26T06:${10 + step * 10}:00Z`, endedAt: `2026-10-26T06:${17 + step * 10}:00Z` });
  Object.assign(s.ops[0], { targetRate: rate, ok, failed, errorRate: failed / (ok + failed), codes: failed ? { SETUP_TIMEOUT: failed } : {} });
  return s;
}
function digestServer(step: number, sigs: Record<string, Record<string, number>>, first: Record<string, Record<string, string>> = {}) {
  return { step, kind: "ramp", window: { start: "", end: "" }, apps: {}, pg: null, logs: { signatures: sigs, exec: [], system: [], firstSeen: first }, prom: null, stub: null, missing: [] } as unknown as import("../collect/collectors.js").StepServer;
}

test("digest: persistent failure after load drops", async () => {
  const { persistentFailure } = await import("../collect/digest.js");
  const steps = [digestStep(1, "ramp", 1, 5, 0, "ok"), digestStep(2, "ramp", 2, 12, 3, "break"), digestStep(3, "confirm", 1, 0, 5, "break")];
  assert.equal(persistentFailure(steps)?.step.step, 3);
  assert.equal(persistentFailure(steps)?.breakStep.step, 2);
  // A confirm step that recovers is a throughput problem, not a persistent one.
  assert.equal(persistentFailure([steps[0], steps[1], digestStep(3, "confirm", 1, 5, 0, "ok")]), null);
  assert.equal(persistentFailure([steps[0]]), null);
});

test("digest: cause dictionary ranks the oversized token over caught master duplicates", async () => {
  const { rankCauses, CAUSES, atAGlance } = await import("../collect/digest.js");
  for (const k of ["sqlite_locked", "uid_duplicate", "stmt_timeout", "oidc_param_too_long", "header_too_large", "restarts", "pg_unique_violation"]) assert.ok(CAUSES[k]?.explain && CAUSES[k]?.action, k);
  const steps = [digestStep(1, "ramp", 1, 5, 0, "ok"), digestStep(2, "ramp", 2, 12, 3, "break"), digestStep(3, "confirm", 1, 0, 5, "break")];
  const server = [
    digestServer(1, { sork2: { uid_duplicate: 3, pg_unique_violation: 5, error_lines: 10 } }),
    digestServer(2, { sork2: { uid_duplicate: 10, pg_unique_violation: 21, error_lines: 42 }, sork5: { stmt_timeout: 1 }, "tidecloak-staging": { oidc_param_too_long: 10 } }, { "tidecloak-staging": { oidc_param_too_long: "2026-10-26T06:24:24Z" } }),
    digestServer(3, { "tidecloak-staging": { oidc_param_too_long: 15 } }),
  ];
  const c = rankCauses(steps, server);
  assert.deepEqual(c.map((x) => [x.id, x.status]), [["oidc_param_too_long", "likely cause"], ["stmt_timeout", "possible contributor"], ["pg_unique_violation", "noise"], ["uid_duplicate", "noise"]]);
  assert.equal(c[0].count, 25);
  assert.equal(c[0].firstSeen, "2026-10-26T06:24:24Z");
  // A real "Failed to add user" turns the duplicates back into suspects.
  server[1].logs!.signatures.sork2.add_user_failed = 2;
  assert.ok(rankCauses(steps, server).every((x) => x.status !== "noise"));
  delete server[1].logs!.signatures.sork2.add_user_failed;
  const glance = atAGlance({ steps, server, abortReason: null }, c).join("\n");
  assert.match(glance, /Result: BREAK\*\* at step 2/);
  assert.match(glance, /Worked fully up to:\*\* 1\.00\/min \(step 1/);
  assert.match(glance, /Most likely cause:\*\* TideCloak ignored an oversized refresh token/);
  assert.match(glance, /Failures continued after load dropped/);
  assert.match(glance, /Load machine or Playwright the limit:\*\* no/);
  assert.match(glance, /Noise, not the cause:\*\* pg_unique_violation x26/);
  assert.match(glance, /Confidence:\*\* high/);
  assert.ok(glance.split("\n").filter((l) => l.startsWith("- ")).length <= 10);
});

test("header_too_large never matches a bare 431; licence cap is an expected limit", async () => {
  const { LOG_SIGNATURES } = await import("../collect/collectors.js");
  // Mirror the KQL "contains" conditions (case-insensitive substring) against sample lines.
  const kqlMatch = (cond: string, line: string) => cond.split(" or ").some((c) => line.toLowerCase().includes(/contains "(.*)"/.exec(c)![1].toLowerCase()));
  for (const t of ["Execution time for Create.Commit: 431 ms", "Execution time for Create.GenShard: 431 ms", "Execution time for Key.PreSign: 431 ms"]) {
    assert.equal(kqlMatch(LOG_SIGNATURES.header_too_large, t), false, t);
    assert.ok(!matchSignatures(t).some((s) => s.id === "HEADER_TOO_LARGE"), t);
  }
  assert.ok(kqlMatch(LOG_SIGNATURES.header_too_large, "HTTP 431 Request Header Fields Too Large"));
  assert.ok(matchSignatures("request failed with status 431").some((s) => s.id === "HEADER_TOO_LARGE"));
  const cap = "Tide error on /Payer/Subscription/Validate: This Subscription entry has exceeded its total concurrent active users of the last month";
  assert.ok(kqlMatch(LOG_SIGNATURES.licence_active_cap, cap));
  assert.ok(matchSignatures(cap).some((s) => s.id === "LICENCE_ACTIVE_CAP"));
  assert.equal(isBreakSignature("LICENCE_ACTIVE_CAP"), false);
});

test("digest: licence cap outranks other causes and the queue is not blamed on the client", async () => {
  const { rankCauses, atAGlance } = await import("../collect/digest.js");
  const steps = [digestStep(1, "ramp", 8, 52, 0, "ok"), digestStep(2, "ramp", 16, 11, 20, "aborted")];
  Object.assign(steps[1].ops[0], { queueWaitP95: 39225, codes: { SIGNUP_STEP2_SUBMITTED: 20 } });
  Object.assign(steps[1].flags, { clientBound: true });
  steps[1].client.cpuMax = 12;
  const server = [digestServer(2, { sork3: { licence_active_cap: 40, stmt_timeout: 2 }, sork2: { uid_duplicate: 4 } })];
  const c = rankCauses(steps, server);
  assert.deepEqual(c.map((x) => [x.id, x.status]), [["licence_active_cap", "expected limit"], ["stmt_timeout", "possible contributor"], ["uid_duplicate", "noise"]]);
  const glance = atAGlance({ steps, server, abortReason: "rolling 30s error rate 100% > 20% (5/5)" }, c).join("\n");
  assert.match(glance, /Result: ABORT, stopped by licence cap \(an expected test limit, not a staging failure\)/);
  assert.match(glance, /Most likely cause:\*\* Test realm hit its licence active-user cap/);
  assert.match(glance, /Playwright the limit:\*\* no \(queue wait inflated by failing signup operations holding browser slots until timeout/);
  assert.match(glance, /Next action:\*\* Raise MaxConcurrentAccountsPerMonth/);
});

test("break rule: soft signatures warn, hard ones break, --strict-signatures restores the old rule", () => {
  const client = { cpuAvg: 10, cpuMax: 10, loopLagP95: 1, maxQueue: {}, poolBusyAvg: {} };
  const ops = (sig: string, failed: number, ok: number) => [{ op: "signup", arrivals: ok + failed, ok, failed, errorRate: failed / (ok + failed), onTimeRatio: 1, p95: 100, dropped: 0, queueWaitP95: 0, signatures: { [sig]: failed } }] as never;
  const soft = judgeStep(ops("GATEWAY", 1, 147), client, { signup: 100 }, DEFAULT_THRESHOLDS);
  assert.equal(soft.break, false);
  assert.deepEqual(soft.warnings, { GATEWAY: 1 });
  assert.ok(soft.reasons.includes("warnings: GATEWAY x1"));
  assert.equal(judgeStep(ops("GATEWAY", 1, 147), client, { signup: 100 }, { ...DEFAULT_THRESHOLDS, strictSignatures: true }).break, true);
  assert.equal(judgeStep(ops("GATEWAY", 10, 90), client, { signup: 100 }, DEFAULT_THRESHOLDS).break, true, "error rate still breaks");
  assert.equal(judgeStep(ops("STATEMENT_TIMEOUT", 1, 147), client, { signup: 100 }, DEFAULT_THRESHOLDS).break, false);
  assert.deepEqual(judgeStep(ops("SQLITE_LOCKED", 1, 147), client, { signup: 100 }, DEFAULT_THRESHOLDS).breakSignatures, ["SQLITE_LOCKED"]);
  assert.ok(matchSignatures("token HTTP 400: temporarily_unavailable").some((s) => s.id === "GATEWAY"));
});

test("digest: signature-only break names its trigger and soft causes stay contributors", async () => {
  const { rankCauses, atAGlance, verdictText, signatureOnlyBreak } = await import("../collect/digest.js");
  const steps = [digestStep(1, "ramp", 16, 82, 0, "ok"), digestStep(2, "ramp", 32, 147, 1, "break")];
  Object.assign(steps[1].ops[0], { signatures: { GATEWAY: 1 }, codes: { TOKEN_MINT_FAILED: 1 } });
  Object.assign(steps[1].flags, { break: true, breakSignatures: ["GATEWAY"], reasons: ["server failure signatures: GATEWAY"] });
  const server = [digestServer(2, { sork5: { stmt_timeout: 9 } })];
  (server[0] as { apps: Record<string, unknown> }).apps = { sork1: { cpuPctMax: 92 } };
  const c = rankCauses(steps, server);
  assert.ok(c.every((x) => x.status !== "likely cause"), JSON.stringify(c.map((x) => [x.id, x.status])));
  assert.ok(c.some((x) => x.id === "high_cpu" && x.apps[0] === "sork1 92%" && x.status === "possible contributor"));
  assert.ok(c.some((x) => x.id === "gateway"));
  assert.equal(signatureOnlyBreak(steps[1]), "broke on 1 gateway error (1%) under strict rules; the current rule only warns on it");
  const glance = atAGlance({ steps, server, abortReason: null }, c).join("\n");
  assert.match(glance, /trigger: server failure signatures: GATEWAY; broke on 1 gateway error \(1%\) under strict rules/);
  assert.match(glance, /Most likely cause:\*\* none stands out/);
  // The same soft signature at a high error rate can lead.
  const hot = [digestStep(1, "ramp", 16, 82, 0, "ok"), digestStep(2, "ramp", 32, 80, 20, "break")];
  assert.equal(rankCauses(hot, server).find((x) => x.lead)?.id, "stmt_timeout");
  const w = digestStep(3, "ramp", 32, 147, 1, "ok");
  w.flags.warnings = { GATEWAY: 1 };
  assert.equal(verdictText(w), "ok (warnings: GATEWAY x1)");
});

test("realm pool spreads round-robin and runs out", () => {
  const p = new RealmPool([{ realm: "a", seats: 2 }, { realm: "b", seats: 2, tideFull: true }]);
  assert.equal(p.isTideFull("b"), true);
  assert.equal(p.isTideFull("a"), false);
  assert.deepEqual([p.take(), p.take(), p.take()], ["a", "b", "a"]);
  p.markFull("b");
  assert.equal(p.take(), null);
  assert.equal(p.remaining(), 0);
  p.giveBack("a");
  assert.equal(p.take(), "a");
});

test("login pool rotates users", () => {
  const p = new LoginUserPool();
  p.add({ userId: "u1", realm: "r", password: "x" });
  p.add({ userId: "u2", realm: "r", password: "x" });
  assert.deepEqual([p.next()?.userId, p.next()?.userId, p.next()?.userId], ["u1", "u2", "u1"]);
});

test("setup names and error codes", () => {
  assert.deepEqual(setupNames({ runId: "r1", emailDomain: "invalid.tide.test", realmPrefix: "lt-pool" }, 3), { realm: "lt-pool-r1-3", email: "lt-r1-pool3@invalid.tide.test" });
  assert.equal(errorCode({ status: 500, ms: 0, text: '{"code":"TIDE-TIDECLOAK-VENDOR_KEYGEN_FAILED"}' }), "TIDE-TIDECLOAK-VENDOR_KEYGEN_FAILED");
  assert.equal(errorCode({ status: 502, ms: 0, text: "bad" }), "HTTP_502");
});

test("scrub removes secrets and tokens", () => {
  const s = scrub("password=hunter22&x=1 token eyJabcdefghijkl.eyJpayload.sig hunter22", ["hunter22"]);
  assert.ok(!s.includes("hunter22"));
  assert.ok(!s.includes("eyJabcdefghijkl"));
});

test("pool queues beyond capacity", async () => {
  const p = new Pool("t", 1);
  const r1 = await p.acquire();
  let got = false;
  const w = p.acquire().then((r) => { got = true; return r; });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(got, false);
  assert.equal(p.queued, 1);
  r1();
  (await w)();
  assert.equal(p.busy, 0);
});

function engineFor(dir: string, ops: OpSpec[], steps: number[], abortErrorRate = 0.2) {
  return new Engine({
    runId: "t", scenario: "unit",
    steps: steps.map((r, i) => ({ index: i + 1, baseRate: r, kind: "ramp" as const })),
    stepMs: 1200, cooldownMs: 0, drainMs: 2000, arrival: "uniform",
    thresholds: { ...DEFAULT_THRESHOLDS, abortErrorRate, abortMinSamples: 5 },
    events: new Jsonl(join(dir, "e.jsonl")), stepsLog: new Jsonl(join(dir, "s.jsonl")),
    monitor: new ClientMonitor([]), log: () => undefined,
  }, ops);
}

test("engine: break triggers one confirm step at the last good rate", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sim-"));
  const pool = new Pool("p", 50);
  let current = 0;
  const op: OpSpec = { name: "x", ratio: 1, pool, maxQueue: 100, run: async (ctx) => {
    current = ctx.step;
    await new Promise((r) => setTimeout(r, 5));
    // Step 2 fails with a server signature; everything else passes.
    return ctx.step === 2 ? { ok: false, code: "E", message: "database is locked" } : { ok: true };
  } };
  const res = await engineFor(dir, [op], [600, 1200, 2400], 1.1).run();
  assert.equal(current, 3);
  assert.deepEqual(res.steps.map((s) => [s.kind, s.verdict]), [["ramp", "ok"], ["ramp", "break"], ["confirm", "ok"]]);
  assert.equal(res.steps[2].baseRate, 600);
  const c = ceilings(res.steps);
  assert.equal(c[0].lastOk, 600);
  assert.equal(c[0].brk, 1200);
});

test("engine: ops lost with their browser are client-side, outside abort and break, and keep arrival steps", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sim-"));
  let n = 0;
  // Every third op dies with its browser; the rest fail at a normal staging rate of zero.
  const op: OpSpec = { name: "x", ratio: 1, pool: new Pool("p", 50), maxQueue: 100, run: async (ctx) => {
    const lost = ++n % 3 === 0;
    ctx.onBrowser?.({ index: lost ? 1 : 0, lost: () => lost });
    await new Promise((r) => setTimeout(r, 5));
    return lost ? { ok: false, code: "SIGNUP_STEP2_SUBMITTED", message: "first-broker-login form did not appear" } : { ok: true };
  } };
  const res = await engineFor(dir, [op], [1200]).run();
  assert.equal(res.abortReason, null, "client-side failures never trip the rolling abort");
  const st = res.steps[0];
  assert.equal(st.ops[0].failed, 0);
  assert.equal(st.ops[0].errorRate, 0);
  assert.ok((st.ops[0].clientLost ?? 0) > 0);
  assert.equal(st.flags.break, false);
  assert.equal(st.flags.clientBound, true, "a third of the ops lost is over 25%");
  const rows = readFileSync(join(dir, "e.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const lostRows = rows.filter((r) => r.clientSide);
  assert.ok(lostRows.length && lostRows.every((r) => r.browser === 1 && r.code === "SIGNUP_STEP2_SUBMITTED"));
  // ts is the arrival time inside the step; endTs is completion.
  for (const r of rows) {
    assert.ok(Date.parse(r.ts) >= st.startMs && Date.parse(r.ts) <= st.startMs + 1200, "arrival inside the step window");
    assert.ok(Date.parse(r.endTs) >= Date.parse(r.ts) + r.latencyMs - 5);
  }
  // A harness exception is client-side too.
  const crash: OpSpec = { name: "x", ratio: 1, pool: new Pool("p", 50), maxQueue: 100, run: async () => { throw new Error("browser.newContext: Target page, context or browser has been closed"); } };
  const r2 = await engineFor(mkdtempSync(join(tmpdir(), "sim-")), [crash], [1200]).run();
  assert.equal(r2.abortReason, null);
  assert.equal(r2.steps[0].verdict, "client-bound");
});

test("browser host replaces a disconnected remote browser and flags in-flight ops", async () => {
  const { BrowserHost } = await import("../scenarios/browser.js");
  type Fake = { connected: boolean; h: Record<string, () => void>; kill: () => void };
  const fakes: Fake[] = [];
  let failReconnect = false;
  const mk = () => {
    const b = {
      connected: true, h: {} as Record<string, () => void>,
      on(e: string, f: () => void) { b.h[e] = f; },
      isConnected: () => b.connected,
      newContext: async () => { if (!b.connected) throw new Error("browser.newContext: Target page, context or browser has been closed"); return { route: async () => undefined, on: () => undefined, close: async () => undefined }; },
      close: async () => undefined,
      kill() { b.connected = false; b.h.disconnected?.(); },
    };
    fakes.push(b);
    return b;
  };
  const logs: string[] = [];
  const tick = () => new Promise((r) => setTimeout(r, 20));
  const host = new BrowserHost({
    headless: true, target: "staging", onProdHit: () => undefined, log: (s) => logs.push(s), endpoint: "azure", remoteBrowsers: 2, keepAliveMs: 0,
    reconnect: async () => { if (failReconnect && fakes.length >= 3) throw new Error("service busy"); return { browser: mk() as never }; },
  });
  await host.start();
  const gc = await host.context();
  assert.equal(gc.lease.lost(), false);
  fakes[gc.lease.index].kill();
  await tick();
  assert.equal(gc.lease.lost(), true, "the op's browser died while it ran");
  assert.equal(fakes.length, 3, "one replacement opened");
  assert.match(logs.join("\n"), new RegExp(`remote browser ${gc.lease.index} lost, reconnected in \\d+ms`));
  const gc2 = await host.context();
  assert.equal(gc2.lease.lost(), false);
  failReconnect = true;
  fakes[2].kill();
  await tick();
  assert.match(logs.join("\n"), /lost, reconnect failed after 3 tries: service busy/);
  assert.equal(host.usage().lost?.length, 2);
  await host.stop();
});

test("report: client-side losses per step and the At a glance line", async () => {
  const { clientLostCounts } = await import("../report.js");
  const { atAGlance, stepsDigest } = await import("../collect/digest.js");
  const dir = mkdtempSync(join(tmpdir(), "sim-"));
  const ev = [{ step: 2, ok: false, code: "DRIVER_CRASH" }, { step: 2, ok: false, code: "X", clientSide: true }, { step: 2, ok: false, code: "Y" }, { step: 1, ok: true }];
  writeFileSync(join(dir, "events.jsonl"), ev.map((e) => JSON.stringify(e)).join("\n") + "\n");
  const lost = clientLostCounts(join(dir, "events.jsonl"));
  assert.deepEqual(lost, { 2: 2 });
  const steps = [digestStep(1, "ramp", 32, 50, 0, "ok"), digestStep(2, "ramp", 64, 20, 1, "ok")];
  const glance = atAGlance({ steps, server: [], abortReason: null, clientLost: lost }, []).join("\n");
  assert.match(glance, /2 operations lost to remote browser crashes\*\* \(client-side, excluded from staging error rate\): step 2 x2/);
  const table = stepsDigest(steps, [], [], lost).join("\n");
  assert.match(table, /\| 2 \| ramp \| [^|]+ \| [^|]+ \| 20 \| 1 \| 2 \|/);
  assert.match(table, /2 lost to remote browser crashes \(client-side\)/);
});

test("engine: hard abort on rolling error rate", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sim-"));
  const op: OpSpec = { name: "x", ratio: 1, pool: new Pool("p", 50), maxQueue: 100, run: async () => ({ ok: false, code: "E" }) };
  const res = await engineFor(dir, [op], [1200, 2400]).run();
  assert.ok(res.abortReason && /error rate/.test(res.abortReason));
  assert.equal(res.steps.length, 1);
  assert.equal(res.steps[0].verdict, "aborted");
});

test("engine: an op can stop the run (realm pool exhausted)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sim-"));
  let n = 0;
  const op: OpSpec = { name: "x", ratio: 1, pool: new Pool("p", 5), maxQueue: 100, run: async (ctx) => {
    if (++n > 3) { ctx.stop("need more realms"); return { ok: false, code: "REALM_POOL_EXHAUSTED", expected: true }; }
    return { ok: true };
  } };
  const res = await engineFor(dir, [op], [1200, 2400]).run();
  assert.equal(res.stopReason, "need more realms");
  assert.equal(res.steps[0].ops[0].failed, 0);
});

test("engine: full queue drops arrivals and marks the step client-bound", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sim-"));
  const op: OpSpec = { name: "x", ratio: 1, pool: new Pool("p", 1), maxQueue: 1, run: async () => {
    await new Promise((r) => setTimeout(r, 300));
    return { ok: true };
  } };
  const res = await engineFor(dir, [op], [1200, 2400]).run();
  assert.equal(res.steps[0].verdict, "client-bound");
  assert.ok(res.steps[0].ops[0].dropped > 0);
  assert.ok(res.stopReason && /client machine/.test(res.stopReason));
});

test("cleanup checklist lists realms and the email pattern", () => {
  const txt = cleanupChecklist({
    runId: "r1", createdAt: "", target: "staging", tcBase: "https://staging.dauth.me", command: "x", args: {},
    emailPattern: "lt-r1-*@invalid.tide.test",
    realms: [{ realm: "lt-pool-r1-1", email: "e", status: "ready", purpose: "pool", createdAt: "", customerId: "cus_1" }],
    users: [{ userId: "lt-r1-1", realm: "lt-pool-r1-1", email: "e", status: "created", at: "" }], notes: [],
  }, "m.json");
  assert.ok(txt.includes("lt-pool-r1-1"));
  assert.ok(txt.includes("lt-r1-*@invalid.tide.test"));
  assert.ok(txt.includes("cus_1"));
});

test("browser endpoint options", async () => {
  const { resolveBrowserOpts, serviceUrlFromDataplane, checkServiceUrl } = await import("../remote.js");
  assert.deepEqual(resolveBrowserOpts(undefined, "staging", 4, 5), { endpoint: "local", remoteBrowsers: 4, contextsPerBrowser: 5 });
  assert.equal(resolveBrowserOpts("azure", "staging", 2, 3).endpoint, "azure");
  assert.throws(() => resolveBrowserOpts("azure", "local", 1, 1), /cannot reach a local stack/);
  assert.throws(() => resolveBrowserOpts("cloud", "staging", 1, 1), /local or azure/);
  assert.throws(() => resolveBrowserOpts("azure", "staging", 0, 1), /remote-browsers/);
  const url = serviceUrlFromDataplane("https://australiaeast.api.playwright.microsoft.com/playwrightworkspaces/021c8a38-318d-4f26-9754-e7406a8870f1");
  assert.equal(url, "wss://australiaeast.api.playwright.microsoft.com/playwrightworkspaces/021c8a38-318d-4f26-9754-e7406a8870f1/browsers");
  assert.equal(checkServiceUrl(url), url);
  assert.throws(() => checkServiceUrl("wss://evil.example.com/browsers"));
  assert.throws(() => checkServiceUrl(undefined), /PLAYWRIGHT_SERVICE_URL/);
});

test("remote browser-minute accounting", async () => {
  const { browserMinutes, usageOf } = await import("../remote.js");
  const t = 1_000_000;
  const sessions = [
    { index: 0, connectMs: 900, openedAt: t, closedAt: t + 90_000 },          // 1.5 min
    { index: 1, connectMs: 1100, openedAt: t, closedAt: null },               // still open: counts to now
    { index: 2, connectMs: null, openedAt: null, closedAt: null, error: "x" }, // never connected
  ];
  assert.equal(browserMinutes(sessions, t + 30_000), 1.5 + 0.5);
  const u = usageOf("azure", sessions, 5, t + 30_000);
  assert.equal(u.remoteBrowsers, 3);
  assert.equal(u.browserMinutes, 2);
  assert.equal(u.estCostUsd, 0.042);
  assert.equal(usageOf("local", [], null).browserMinutes, 0);
});

test("redaction strips connection strings, keys and tokens", async () => {
  const { redact, redactDeep } = await import("../collect/az.js");
  const s = redact('Host=db;Password=hunter2;User=x sk_test_abc123 rk_live_zzz whsec_q1 "access_token":"abc" eyJaaaaaaaaaaaa.bbb.ccc');
  for (const bad of ["hunter2", "abc123", "zzz", "q1", '"abc"', "eyJaaaaaaaaaaaa"]) assert.ok(!s.includes(bad), `leaked ${bad} in ${s}`);
  assert.deepEqual(redactDeep({ a: ["Pwd=x;"] }), { a: ["Pwd=[REDACTED];"] });
});

test("stub delta flags passthrough beyond the price catalogue", async () => {
  const { stubDelta } = await import("../collect/collectors.js");
  const a = { decisions: { stubbed: 1, passthrough: 1 }, byRoute: { "stubbed POST /v1/customers": 1, "passthrough GET /v1/prices": 1 } };
  const ok = stubDelta(a, { decisions: { stubbed: 3, passthrough: 2 }, byRoute: { "stubbed POST /v1/customers": 2, "stubbed POST /v1/subscriptions": 1, "passthrough GET /v1/prices": 2 } });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.decisions, { stubbed: 2, passthrough: 1 });
  // A passthrough GET is background traffic from other realms, not a leak.
  const bg = stubDelta(a, { decisions: {}, byRoute: { ...a.byRoute, "passthrough GET /v1/subscriptions/{id}": 1 } });
  assert.equal(bg.ok, true);
  // A load-test CREATE passing through IS a leak.
  const bad = stubDelta(a, { decisions: {}, byRoute: { ...a.byRoute, "passthrough POST /v1/customers": 1 } });
  assert.equal(bad.ok, false);
  assert.deepEqual(bad.unexpectedPassthrough, { "passthrough POST /v1/customers": 1 });
});

function fakeStep(step: number, verdict: string, p95: number, opts: { cpu?: number; queue?: number; keygen?: number } = {}) {
  return {
    step, kind: "ramp", baseRate: step, startedAt: "", endedAt: "", startMs: step * 1000, endMs: step * 1000 + 500,
    ops: [{ op: "signup", targetRate: 1, arrivals: 10, completed: 10, ok: 10, failed: 0, expected: 0, dropped: 0, late: 0, errorRate: 0, onTimeRatio: 1, okPerMin: 1,
      p50: p95, p95, p99: p95, queueWaitP95: opts.queue ?? 0, codes: {}, signatures: {}, phaseP95: { enclave_load: 900, keygen_wait: opts.keygen ?? 1300 } }],
    client: { cpuAvg: opts.cpu ?? 20, cpuMax: opts.cpu ?? 20, loopLagP95: 5, maxQueue: {}, poolBusyAvg: {} },
    flags: { knee: false, break: false, clientBound: false, breakSignatures: [], reasons: [] },
    verdict,
  } as unknown as import("../engine.js").StepSummary;
}

function fakeServer(step: number, o: { sorkCpu?: number; submitP95?: number; sqlite?: number; pgConn?: number } = {}) {
  return {
    step, kind: "ramp", window: { start: "", end: "" },
    apps: { sork1: { cpuPctAvg: 10, cpuPctMax: o.sorkCpu ?? 20, memPctAvg: 30, memPctMax: 30, cpuCoresMax: 0.1, limitCores: 0.5, replicasMax: 1, restarts: 0, requests: 10, respMsAvg: 10, respMsMax: 20 } },
    pg: { cpuPctAvg: 10, cpuPctMax: 15, memPctMax: 60, activeConnMax: o.pgConn ?? 20, maxConnections: 100, connPctMax: o.pgConn ?? 20, iopsPctMax: 1, cpuCreditsMin: 200, connectionsFailed: 0 },
    logs: { signatures: { sork3: { sqlite_locked: o.sqlite ?? 0, uid_duplicate: o.sqlite ? 5 : 0, seat_cap: 2, error_lines: 0 } }, exec: [{ app: "sork1", op: "Master.SubmitUser", n: 10, p50: 20, p95: o.submitP95 ?? 40, max: 60 }], system: [] },
    prom: null, stub: null, missing: [],
  } as unknown as import("../collect/collectors.js").StepServer;
}

test("analysis: server crossing first gives server-bound with ranked evidence", async () => {
  const { analyse } = await import("../collect/analysis.js");
  const client = [fakeStep(1, "ok", 5000), fakeStep(2, "ok", 6000), fakeStep(3, "knee", 12000, { keygen: 4000 })];
  const server = [fakeServer(1), fakeServer(2, { submitP95: 400 }), fakeServer(3, { submitP95: 900, sqlite: 3 })];
  const inv = { at: "", apps: [{ name: "sork1", role: "master ORK" }, { name: "sork3", role: "ORK + payer" }], pg: null, workspaces: [], harnessCommit: null, missing: [] } as unknown as import("../collect/collectors.js").Inventory;
  const [a] = analyse(client, server, inv);
  assert.equal(a.step, 3);
  assert.match(a.verdict, /^server-bound/);
  assert.equal(a.first?.component, "master ORK SubmitUser (sork1)");
  assert.equal(a.first?.step, 2);
  assert.ok(a.ranked.some((s) => s.component === "SQLite store (sork3)" && s.value === 3));
  assert.ok(a.ranked.some((s) => s.component === "master ORK SubmitUser concurrent UID insert (sork3, see master-libs PR #30)" && s.value === 5));
  assert.ok(!a.ranked.some((s) => s.metric === "log seat_cap"), "seat cap is expected, not a suspect");
  assert.ok(a.ranked.some((s) => s.component.startsWith("phase signup.keygen_wait")));
  assert.match(a.slowestOrk ?? "", /sork1 \(Master.SubmitUser p95 900ms/);
  assert.match(a.slowestPhase ?? "", /keygen_wait p95 4000ms \(3.1x baseline 1300ms\)/);
});

test("analysis: client CPU crossing first gives client-bound", async () => {
  const { analyse } = await import("../collect/analysis.js");
  const client = [fakeStep(1, "ok", 5000), fakeStep(2, "client-bound", 9000, { cpu: 92 })];
  const server = [fakeServer(1), fakeServer(2, { sorkCpu: 85 })];
  const [a] = analyse(client, server, null);
  assert.match(a.verdict, /^mixed|^client-bound/);
  const client2 = [fakeStep(1, "ok", 5000), fakeStep(2, "knee", 9000, { cpu: 95 }), fakeStep(3, "break", 9000, { cpu: 95 })];
  const server2 = [fakeServer(1), fakeServer(2), fakeServer(3, { pgConn: 90 })];
  const res = analyse(client2, server2, null);
  assert.match(res[0].verdict, /^client-bound/);
  assert.ok(res[1].ranked.some((s) => s.component === "Postgres dauthme-staging" && s.metric === "connections % of max"));
});

test("analysis: nothing crossed says so", async () => {
  const { analyse } = await import("../collect/analysis.js");
  const [a] = analyse([fakeStep(1, "ok", 5000)], [fakeServer(1)], null);
  assert.match(a.verdict, /no threshold crossed/);
});

test("console setup realm and email naming match the http setup", async () => {
  const { setupNames } = await import("../scenarios/setup.js");
  // The console slugifies the project name to the realm, so the project name IS the realm name.
  assert.deepEqual(setupNames({ runId: "r9", emailDomain: "invalid.tide.test", realmPrefix: "lt-ws" }, 2), { realm: "lt-ws-r9-2", email: "lt-r9-ws2@invalid.tide.test" });
  const { REALM_SLUG } = { REALM_SLUG: /^[a-z0-9][a-z0-9-]{0,60}$/ };
  assert.ok(REALM_SLUG.test("lt-ws-r9-2"), "realm name is a valid console slug");
});
