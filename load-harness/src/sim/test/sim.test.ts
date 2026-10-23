// Unit tests for the simulator's pure logic and the engine loop. No network.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
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
