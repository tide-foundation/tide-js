//
// Browserless multi-VU driver for the cmkOnly login flow (Load-test v2 R5).
//
// Parallel of ../loadtest/index.ts but built on the protocol module's
// NodeCmkClient instead of Playwright. Same env vars, same ramp shape,
// same JSONL row schema (modulo the v2 `phases` keys, which are coarser
// — fetch1 / crypto / fetch2 / total — because the protocol module only
// instruments those four steps).
//
// Architecture summary:
//   1. NO Playwright. Per-VU isolation comes from a per-iteration
//      NodeCmkClient call, which internally mints fresh ephemeral
//      keys and uses a per-call CookieJar (see cookie-jar.ts).
//   2. CONCURRENCY virtual users. Each VU is an async loop that runs
//      one login per iteration and records a JSONL row, until
//      RAMP_S + DURATION_S elapses.
//   3. Ramp scheduler: spawn VU #k at t = k * (RAMP_S/CONCURRENCY) so
//      the floor reaches CONCURRENCY at t = RAMP_S.
//   4. In-flight iterations are NOT cancelled when the deadline fires
//      — let them complete so we get a real terminal phase timing.
//
// Important non-goals:
//   * No OIDC code exchange. R19 parking lot — we capture the OIDC
//     `code` + `state` from Fetch 2 and stop. Exchanging the code for
//     an access_token would push us back into the SWE-affected /token
//     code path that the v1 driver already measures.
//   * No fixture writing.
//   * Single user pool. R5 deliberately hammers one user to find the
//     TideCloak `userIdThrottlingConfig` ceiling. R6 will expand the
//     pool.
//
// Security:
//   * Passwords come from LOAD_TEST_USERS_PATH (gitignored). They are
//     forwarded into NodeCmkClient.login() which scrubs them out of
//     every Error.message it produces. We re-scrub at this layer in
//     case a future regression slips through.
//   * Per-iteration JSONL does NOT contain the password, the OIDC
//     code, sessionKey material, or vendorEncryptedData.
//   * userId is logged verbatim — operator-visible only.
//

import "./undici-setup.js";
import { readFileSync, mkdirSync, openSync, closeSync, writeSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";

import { NodeCmkClient } from "./nodeCmkClient.js";
import type { LoginResult } from "./types.js";
import type { LoadTestUser, LoadTestUsersFile } from "../warmup/types.js";
import type { RealmFixture } from "../runSign.js";

declare const fetch: typeof globalThis.fetch;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const TC_BASE      = (process.env.TIDECLOAK_BASE_URL ?? "https://staging.dauth.me").replace(/\/+$/, "");
const TC_REALM     = process.env.TIDECLOAK_REALM     ?? "tide-metrics-load";
const OIDC_CLIENT  = process.env.OIDC_CLIENT_ID      ?? "tide-loadtest-harness";
const CALLBACK_URL = process.env.OIDC_REDIRECT_URI   ?? "http://localhost:3000/callback";
const HOME_ORK_URL = (process.env.HOME_ORK_URL       ?? process.env.WARMUP_HOME_ORK ?? "https://sork1.tideprotocol.com").replace(/\/+$/, "");

const USERS_PATH   = process.env.LOAD_TEST_USERS_PATH ?? "./load-test-users.json";
const RESULTS_PATH = process.env.RESULTS_PATH         ?? "./loadtest-results-v2-node.jsonl";
const CONCURRENCY  = Math.max(1, parseInt(process.env.CONCURRENCY ?? "10", 10));
const RAMP_S       = Math.max(0, parseInt(process.env.RAMP_S      ?? "30", 10));
const DURATION_S   = Math.max(1, parseInt(process.env.DURATION_S  ?? "120", 10));

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function logInfo(msg: string): void {
  // eslint-disable-next-line no-console
  console.log(`[protocol-loadtest] ${msg}`);
}
function logWarn(msg: string): void {
  // eslint-disable-next-line no-console
  console.warn(`[protocol-loadtest] WARN ${msg}`);
}
function logError(msg: string): void {
  // eslint-disable-next-line no-console
  console.error(`[protocol-loadtest] ERROR ${msg}`);
}

// ---------------------------------------------------------------------------
// User pool (round-robin)
// ---------------------------------------------------------------------------

function loadUsers(path: string): LoadTestUser[] {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (e) {
    throw new Error(
      `failed to read users file at ${path}: ${(e as Error).message}. ` +
        `Set LOAD_TEST_USERS_PATH or copy load-test-users-sample.json.`,
    );
  }
  let parsed: LoadTestUsersFile;
  try {
    parsed = JSON.parse(raw) as LoadTestUsersFile;
  } catch (e) {
    throw new Error(`users file at ${path} is not valid JSON: ${(e as Error).message}`);
  }
  if (!parsed || !Array.isArray(parsed.users) || parsed.users.length === 0) {
    throw new Error(`users file at ${path} has no users[]`);
  }
  for (const u of parsed.users) {
    if (typeof u?.userId !== "string" || u.userId.length === 0) {
      throw new Error(`users file: missing userId in entry`);
    }
    if (typeof u?.password !== "string" || u.password.length === 0) {
      throw new Error(`users file: missing password for ${u.userId}`);
    }
  }
  return parsed.users;
}

class UserPool {
  private users: LoadTestUser[];
  private idx = 0;
  constructor(users: LoadTestUser[]) {
    if (users.length === 0) throw new Error("UserPool: empty users[]");
    this.users = users;
  }
  next(): LoadTestUser {
    const u = this.users[this.idx % this.users.length];
    this.idx++;
    return u;
  }
  size(): number { return this.users.length; }
}

// ---------------------------------------------------------------------------
// Per-iteration result schema (parallels v1 IterationResult)
//
// v1 phases: oidc_begin / nav_to_swe / swe_form_fill / swe_sign_in_click /
//            wait_for_callback / oidc_await / total.
// v2 phases: fetch1 / crypto / fetch2 / total.
//
// We keep the snake_case `*_ms` naming + `total_ms` from v1 so existing
// JSONL analysers can read both schemas with `phases.total_ms`.
// ---------------------------------------------------------------------------

interface PhaseTimings {
  fetch1_ms?: number;
  crypto_ms?: number;
  fetch2_ms?: number;
  total_ms:   number;
}

type FailurePhase = "fetch1" | "crypto" | "fetch2" | "setup" | "unknown";

interface IterationError {
  code:    string;     // grouped code, e.g. UID_THROTTLED, NET_FAILURE, FETCH2_REJECTED
  message: string;     // brief, password-scrubbed
}

interface IterationResult {
  ts:        string;       // ISO timestamp of iteration START
  vu:        number;       // VU id (1-based)
  iter:      number;       // iteration ordinal for this VU
  userId:    string;
  ok:        boolean;
  phases:    PhaseTimings;
  failedAt?: FailurePhase;
  error?:    IterationError | null;
}

function now(): number { return performance.now(); }

function redactPwd(s: string, password: string): string {
  if (!password || password.length < 3) return s;
  const enc = encodeURIComponent(password);
  return s.split(password).join("[REDACTED]").split(enc).join("[REDACTED]");
}

// Map a raw protocol-layer error message to a coarse failure phase and
// grouped error code. The message format is set by nodeCmkClient.ts /
// tideAuth.ts — both prefix with "Fetch 1:" / "Fetch 2:" / crypto. If
// new error shapes appear, default to UNKNOWN so failures are still
// visible in the summary.
function classifyError(rawMessage: string, phases: PhaseTimings): { failedAt: FailurePhase; code: string } {
  const m = rawMessage;

  // Tide-domain errors we can recognise from server payloads.
  if (/TIDE-TIDECLOAK-TOKEN-NO_USER_CONTEXT/i.test(m)) {
    return { failedAt: classifyPhase(phases), code: "NO_USER_CONTEXT" };
  }
  if (/throttl|too[\s_-]*many[\s_-]*requests|429/i.test(m)) {
    return { failedAt: classifyPhase(phases), code: "UID_THROTTLED" };
  }
  if (/SocketError|ECONNRESET|ETIMEDOUT|ECONNREFUSED|UND_ERR_/i.test(m)) {
    return { failedAt: classifyPhase(phases), code: "NET_FAILURE" };
  }
  if (/^Fetch 1:/i.test(m)) {
    if (/KC_AUTH_SESSION_HASH/i.test(m)) return { failedAt: "fetch1", code: "MISSING_KC_AUTH_HASH" };
    return { failedAt: "fetch1", code: "FETCH1_REJECTED" };
  }
  if (/KC_AUTH_SESSION_HASH cookie was NOT captured/i.test(m)) {
    return { failedAt: "fetch1", code: "MISSING_KC_AUTH_HASH" };
  }
  if (/^Fetch 2:/i.test(m)) {
    if (/callback error=/i.test(m))   return { failedAt: "fetch2", code: "FETCH2_CALLBACK_ERROR" };
    if (/expected 30x/i.test(m))      return { failedAt: "fetch2", code: "FETCH2_REJECTED" };
    return { failedAt: "fetch2", code: "FETCH2_OTHER" };
  }
  if (/Crypto flow|HashToPoint|GetKeyInfo|Convert|Authenticate|gVRK|authorizerPack/i.test(m)) {
    return { failedAt: "crypto", code: "CRYPTO_FAILED" };
  }
  return { failedAt: classifyPhase(phases), code: "UNKNOWN" };
}

// Best-effort phase classification when no marker is present in the
// message — use the highest-numbered phase that actually got a timing.
function classifyPhase(phases: PhaseTimings): FailurePhase {
  if (typeof phases.fetch2_ms === "number") return "fetch2";
  if (typeof phases.crypto_ms === "number") return "crypto";
  if (typeof phases.fetch1_ms === "number") return "fetch1";
  return "setup";
}

// ---------------------------------------------------------------------------
// Single iteration runner
// ---------------------------------------------------------------------------

interface RunIterationArgs {
  vuId:   number;
  iter:   number;
  user:   LoadTestUser;
  client: NodeCmkClient;
  realm:  RealmFixture;
}

async function runLoginIteration(args: RunIterationArgs): Promise<IterationResult> {
  const ts = new Date().toISOString();
  const result: IterationResult = {
    ts,
    vu:     args.vuId,
    iter:   args.iter,
    userId: args.user.userId,
    ok:     false,
    phases: { total_ms: 0 },
  };

  let login: LoginResult;
  try {
    login = await args.client.login(args.user, args.realm);
  } catch (e) {
    // NodeCmkClient.login is designed to never throw — covered defensively.
    const raw = e instanceof Error ? e.message : String(e);
    const scrubbed = redactPwd(raw, args.user.password);
    const { failedAt, code } = classifyError(scrubbed, result.phases);
    result.failedAt = failedAt;
    result.error    = { code, message: truncate(scrubbed, 500) };
    return result;
  }

  // Mirror v2 LoginResult.phases (camelCase) into v1 snake_case schema.
  result.phases = {
    total_ms:  login.phases.totalMs,
    fetch1_ms: login.phases.fetch1Ms,
    crypto_ms: login.phases.cryptoMs,
    fetch2_ms: login.phases.fetch2Ms,
  };

  if (login.ok) {
    result.ok    = true;
    result.error = null;
    return result;
  }

  // Failed login — classify and surface.
  const scrubbed = redactPwd(login.message ?? "unknown failure", args.user.password);
  const { failedAt, code } = classifyError(scrubbed, result.phases);
  result.ok       = false;
  result.failedAt = failedAt;
  result.error    = { code, message: truncate(scrubbed, 500) };
  return result;
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + `…[+${s.length - max}b]`;
}

// ---------------------------------------------------------------------------
// JSONL sink — same model as the v1 driver (openSync + writeSync; each row
// is well under PIPE_BUF, so writes are atomic against concurrent VUs in
// the same process).
// ---------------------------------------------------------------------------

class JsonlSink {
  private fd: number | null = null;
  private path: string;
  private rowCount = 0;
  constructor(path: string) { this.path = path; }
  open(): void {
    mkdirSync(dirname(resolvePath(this.path)), { recursive: true });
    this.fd = openSync(this.path, "w");
  }
  write(row: IterationResult): void {
    if (this.fd === null) throw new Error("JsonlSink.write before open");
    const line = JSON.stringify(row) + "\n";
    writeSync(this.fd, line);
    this.rowCount++;
  }
  close(): void {
    if (this.fd !== null) {
      closeSync(this.fd);
      this.fd = null;
    }
  }
  count(): number { return this.rowCount; }
  filePath(): string { return resolvePath(this.path); }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

function percentile(sorted: number[], p: number): number | null {
  if (sorted.length === 0) return null;
  const k = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((p / 100) * sorted.length) - 1),
  );
  return sorted[k];
}

interface Summary {
  startedAt:           string;
  endedAt:             string;
  config: {
    tcBase:            string;
    tcRealm:           string;
    clientId:          string;
    homeOrkUrl:        string;
    concurrency:       number;
    rampS:             number;
    durationS:         number;
    userPoolSize:      number;
    resultsPath:       string;
  };
  totalIterations:     number;
  successCount:        number;
  failureCount:        number;
  successRate:         number;          // 0..1
  peakConcurrency:     number;
  total_ms: {
    min: number | null;
    p50: number | null;
    p90: number | null;
    p95: number | null;
    p99: number | null;
    max: number | null;
    mean: number | null;
  };
  failuresByPhase:     Record<string, number>;
  failuresByCode:      Record<string, number>;
}

function summarise(
  rows: IterationResult[],
  config: Summary["config"],
  startedAt: string,
  endedAt: string,
  peakConcurrency: number,
): Summary {
  const totals = rows
    .filter((r) => r.ok && typeof r.phases.total_ms === "number")
    .map((r) => r.phases.total_ms)
    .sort((a, b) => a - b);
  const min  = totals.length ? totals[0] : null;
  const max  = totals.length ? totals[totals.length - 1] : null;
  const mean = totals.length
    ? Math.round(totals.reduce((a, b) => a + b, 0) / totals.length)
    : null;

  const failuresByPhase: Record<string, number> = {};
  const failuresByCode:  Record<string, number> = {};
  for (const r of rows) {
    if (r.ok) continue;
    const ph = r.failedAt ?? "unknown";
    failuresByPhase[ph] = (failuresByPhase[ph] ?? 0) + 1;
    const code = r.error?.code ?? "UNKNOWN";
    failuresByCode[code] = (failuresByCode[code] ?? 0) + 1;
  }

  const successCount = rows.filter((r) => r.ok).length;
  return {
    startedAt,
    endedAt,
    config,
    totalIterations: rows.length,
    successCount,
    failureCount:    rows.length - successCount,
    successRate:     rows.length === 0 ? 0 : successCount / rows.length,
    peakConcurrency,
    total_ms: {
      min,
      p50:  percentile(totals, 50),
      p90:  percentile(totals, 90),
      p95:  percentile(totals, 95),
      p99:  percentile(totals, 99),
      max,
      mean,
    },
    failuresByPhase,
    failuresByCode,
  };
}

// ---------------------------------------------------------------------------
// VU loop + ramp scheduler
// ---------------------------------------------------------------------------

interface RunCtx {
  client:          NodeCmkClient;
  realm:           RealmFixture;
  pool:            UserPool;
  deadlineMs:      number;
  sink:            JsonlSink;
  activeVUs:       { value: number };
  peakConcurrency: { value: number };
}

async function vuLoop(ctx: RunCtx, vuId: number): Promise<void> {
  ctx.activeVUs.value++;
  if (ctx.activeVUs.value > ctx.peakConcurrency.value) {
    ctx.peakConcurrency.value = ctx.activeVUs.value;
  }
  try {
    let iter = 0;
    while (Date.now() < ctx.deadlineMs) {
      iter++;
      const user = ctx.pool.next();
      let row: IterationResult;
      try {
        row = await runLoginIteration({
          vuId,
          iter,
          user,
          client: ctx.client,
          realm:  ctx.realm,
        });
      } catch (e) {
        // Belt-and-braces — runLoginIteration also wraps.
        row = {
          ts:       new Date().toISOString(),
          vu:       vuId,
          iter,
          userId:   user.userId,
          ok:       false,
          phases:   { total_ms: 0 },
          failedAt: "setup",
          error:    {
            code:    "DRIVER_CRASH",
            message: truncate(redactPwd((e as Error).message, user.password), 500),
          },
        };
      }
      ctx.sink.write(row);
    }
  } finally {
    ctx.activeVUs.value--;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function scheduleVUs(ctx: RunCtx, concurrency: number, rampS: number): Promise<void> {
  const spawnGapMs = concurrency <= 1 ? 0 : Math.round((rampS * 1000) / concurrency);
  const vuPromises: Promise<void>[] = [];
  for (let k = 0; k < concurrency; k++) {
    if (k > 0 && spawnGapMs > 0) {
      if (Date.now() >= ctx.deadlineMs) break;
      await sleep(spawnGapMs);
    }
    const vuId = k + 1;
    logInfo(`VU ${vuId}/${concurrency} starting`);
    vuPromises.push(
      vuLoop(ctx, vuId).catch((e) => {
        logWarn(`VU ${vuId} crashed: ${(e as Error).message}`);
      }),
    );
  }
  await Promise.all(vuPromises);
}

// ---------------------------------------------------------------------------
// Optional sanity check: does the home ORK respond to ANY HEAD request
// before we spawn VUs? Cheap, and a totally dead ORK URL will otherwise
// cause every single iteration to fail at GetKeyInfo. We DO NOT treat a
// non-200 here as fatal — the home ORK may not expose a / route — only
// a transport-layer failure (DNS / TCP) aborts.
// ---------------------------------------------------------------------------

async function preflightHomeOrk(url: string): Promise<void> {
  try {
    await fetch(url, { method: "HEAD" });
  } catch (e) {
    throw new Error(`Home ORK ${url} unreachable: ${(e as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<number> {
  const startedAt = new Date().toISOString();
  const startedMonotonic = Date.now();

  logInfo(
    `config: concurrency=${CONCURRENCY} ramp=${RAMP_S}s duration=${DURATION_S}s ` +
      `tcBase=${TC_BASE} realm=${TC_REALM} client=${OIDC_CLIENT} homeOrk=${HOME_ORK_URL} ` +
      `resultsPath=${RESULTS_PATH}`,
  );

  // 1. Users.
  let users: LoadTestUser[];
  try {
    users = loadUsers(USERS_PATH);
  } catch (e) {
    logError((e as Error).message);
    return 1;
  }
  logInfo(`loaded ${users.length} user(s) from ${USERS_PATH}`);

  // 2. Home ORK transport sanity check.
  try {
    await preflightHomeOrk(HOME_ORK_URL);
    logInfo(`home ORK ${HOME_ORK_URL} reachable`);
  } catch (e) {
    logError((e as Error).message);
    return 1;
  }

  // 3. Sink.
  const sink = new JsonlSink(RESULTS_PATH);
  try {
    sink.open();
  } catch (e) {
    logError(`failed to open results sink at ${RESULTS_PATH}: ${(e as Error).message}`);
    return 1;
  }
  logInfo(`writing JSONL to ${sink.filePath()}`);

  // 4. Shared NodeCmkClient. Stateless across iterations; each call
  //    mints its own ephemeral keys and CookieJar. Shared between VUs is
  //    safe — no instance-level mutable state.
  const client = new NodeCmkClient({
    tcBase:      TC_BASE,
    tcRealm:     TC_REALM,
    clientId:    OIDC_CLIENT,
    callbackUrl: CALLBACK_URL,
    homeOrkUrl:  HOME_ORK_URL,
  });

  // The RealmFixture is only used by NodeCmkClient.login() for the
  // diagnostic message field — same stub the protocol smoke CLI uses.
  const realm: RealmFixture = {
    realm:      TC_REALM,
    vvkid:      "<protocol-loadtest-stub>",
    vvkPublic:  "<protocol-loadtest-stub>",
    voucherURL: "<protocol-loadtest-stub>",
    homeOrkUrl: HOME_ORK_URL,
    orks:       [],
  };

  // 5. Run the test.
  const deadlineMs = startedMonotonic + (RAMP_S + DURATION_S) * 1000;
  const ctx: RunCtx = {
    client,
    realm,
    pool:            new UserPool(users),
    deadlineMs,
    sink,
    activeVUs:       { value: 0 },
    peakConcurrency: { value: 0 },
  };

  const heartbeat = setInterval(() => {
    const elapsedS = Math.round((Date.now() - startedMonotonic) / 1000);
    logInfo(
      `t=${elapsedS}s activeVUs=${ctx.activeVUs.value}/${CONCURRENCY} ` +
        `iters=${sink.count()} peak=${ctx.peakConcurrency.value}`,
    );
  }, 5_000);

  try {
    await scheduleVUs(ctx, CONCURRENCY, RAMP_S);
  } finally {
    clearInterval(heartbeat);
    sink.close();
  }

  // 6. Summary.
  const endedAt = new Date().toISOString();
  let rows: IterationResult[] = [];
  try {
    const raw = readFileSync(sink.filePath(), "utf8");
    rows = raw
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l) as IterationResult);
  } catch (e) {
    logWarn(`could not re-read results for summary: ${(e as Error).message}`);
  }

  const summary = summarise(
    rows,
    {
      tcBase:        TC_BASE,
      tcRealm:       TC_REALM,
      clientId:      OIDC_CLIENT,
      homeOrkUrl:    HOME_ORK_URL,
      concurrency:   CONCURRENCY,
      rampS:         RAMP_S,
      durationS:     DURATION_S,
      userPoolSize:  users.length,
      resultsPath:   sink.filePath(),
    },
    startedAt,
    endedAt,
    ctx.peakConcurrency.value,
  );

  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ summary }, null, 2));

  if (summary.totalIterations === 0) {
    logError("zero iterations completed");
    return 1;
  }
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    logError(`fatal: ${(e as Error)?.stack ?? String(e)}`);
    process.exit(1);
  },
);
