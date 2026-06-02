//
// Login-flow load driver (Option F, R22).
//
// Drives N concurrent OIDC logins against the harness server's
// /warmup/oidc/begin + /warmup/oidc/await pair for a fixed duration,
// recording per-login latency and a per-phase breakdown. Output is JSONL
// (one row per iteration) plus a summary JSON printed to stdout at end.
//
// Architecture summary:
//   1. Single Playwright Chromium browser, headless.
//   2. CONCURRENCY virtual users (VUs). Each VU is an async loop that:
//        a. opens a fresh BrowserContext (clean cookie jar),
//        b. runs ONE login iteration timed phase-by-phase,
//        c. closes the context, increments iter counter, repeats until
//           the global deadline is reached.
//   3. Ramp scheduler: spawns VU #k at time t_k = k * (RAMP_S/CONCURRENCY),
//      so the floor reaches CONCURRENCY at t = RAMP_S, then runs flat
//      until t = RAMP_S + DURATION_S.
//   4. Realm bootstrap is done ONCE before any VU starts (reuses
//      warmup/realm.ts). The bootstrap result isn't consumed by the
//      login flow directly (it's the realm-level public state runSign
//      needs), but we keep it for parity with the warm-up so a
//      misconfigured realm fails fast before we open a single browser.
//
// Important non-goals:
//   * NO fixture writing. The iteration calls the same underlying
//     captureUserFixture-style primitives but discards the result.
//   * NO sessKey/tideDoken capture (the in-page pump is still installed
//     because oidc.ts's realm-gated init script is the safer code path
//     to reuse — see "Carve-out pump reuse" below — but its result is
//     ignored). The pump's failure is NOT a load-test failure.
//   * NO Locust. Single-Node driver only; browser-per-VU concurrency cap.
//
// Security:
//   * Passwords come from LOAD_TEST_USERS_PATH (gitignored).
//     fillCustomInput() in oidc.ts is the sole egress, same as warmup.
//   * Per-iteration output JSON does NOT contain the password, the
//     doken, the refresh token, or any sessKey material.
//   * userId is logged verbatim. The brief asks for redaction in the
//     reported sample if it's anything other than `metrics-load-001`;
//     that redaction happens in the report this driver produces, not
//     in the JSONL file (which the operator owns).
//

import "../shims.js";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright";
import { readFileSync, mkdirSync, writeFileSync, openSync, closeSync, writeSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";

import { bootstrapRealmFixture } from "../warmup/realm.js";
import {
  beginFlow,
  awaitFlow,
  installCarveOutPump,
  sweFormFill,
  sweClickSignIn,
} from "../warmup/oidc.js";
import type {
  HarnessHealth,
  LoadTestUser,
  LoadTestUsersFile,
} from "../warmup/types.js";
import type { RealmFixture } from "../runSign.js";

declare const fetch: typeof globalThis.fetch;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const HARNESS_URL    = (process.env.HARNESS_URL ?? "http://localhost:3000").replace(/\/+$/, "");
const USERS_PATH     = process.env.LOAD_TEST_USERS_PATH ?? "./load-test-users.json";
const RESULTS_PATH   = process.env.RESULTS_PATH ?? "./loadtest-results.json";
const CONCURRENCY    = Math.max(1, parseInt(process.env.CONCURRENCY ?? "10", 10));
const RAMP_S         = Math.max(0, parseInt(process.env.RAMP_S ?? "30", 10));
const DURATION_S     = Math.max(1, parseInt(process.env.DURATION_S ?? "120", 10));
const HEADLESS       = (process.env.LOADTEST_HEADLESS ?? "true").toLowerCase() !== "false";
const HOME_ORK_URL   = (process.env.WARMUP_HOME_ORK ?? "https://sork1.tideprotocol.com").replace(/\/+$/, "");

// Same fallback values as warmup/index.ts. vvkid/vvkPublic aren't
// fetchable without admin auth; we seed them but never rely on them
// for the load test path. (The load test doesn't sign — it just logs
// in — so the realm fixture is only used to fail-fast on a totally
// broken realm config, not consumed per-iteration.)
const FALLBACK_REALM: Partial<RealmFixture> = {
  vvkid:     "e683904fedb0c52e5a04c41e005df373f9fce407b6d436f750d489672c0cbc6b",
  vvkPublic: "e683904fedb0c52e5a04c41e005df373f9fce407b6d436f750d489672c0cbc6b",
};

// Per-iteration ceiling for the await-callback wait. Reuses the same
// rationale as warmup/oidc.ts DEFAULT_AWAIT_TIMEOUT_MS (120s for the
// full sign-in chain on slow staging). DURATION_S is allowed to exceed
// this — the per-iter timeout caps individual VUs, not the test.
const ITER_AWAIT_TIMEOUT_MS = 120_000;
const ITER_NAV_TIMEOUT_MS   = 90_000;

// ---------------------------------------------------------------------------
// Logging (operator-visible only — no key material, ever)
// ---------------------------------------------------------------------------

function logInfo(msg: string): void {
  // eslint-disable-next-line no-console
  console.log(`[loadtest] ${msg}`);
}
function logWarn(msg: string): void {
  // eslint-disable-next-line no-console
  console.warn(`[loadtest] WARN ${msg}`);
}
function logError(msg: string): void {
  // eslint-disable-next-line no-console
  console.error(`[loadtest] ERROR ${msg}`);
}

// ---------------------------------------------------------------------------
// User pool
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

// Round-robin pool — Keycloak's default session policy allows the same
// user to log in repeatedly, so a single-element pool is supported.
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
}

// ---------------------------------------------------------------------------
// Harness health check (one-shot before VUs spawn)
// ---------------------------------------------------------------------------

async function fetchHarnessHealth(harnessUrl: string): Promise<HarnessHealth> {
  let res: Response;
  try {
    res = await fetch(`${harnessUrl}/health`);
  } catch (e) {
    throw new Error(
      `harness server at ${harnessUrl} is unreachable: ${(e as Error).message}. ` +
        `Start it with: cd load-harness && npm start`,
    );
  }
  if (!res.ok) {
    throw new Error(`harness /health returned ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as HarnessHealth;
}

// ---------------------------------------------------------------------------
// Per-iteration login flow (instrumented)
//
// Phases:
//   oidc_begin          — POST /warmup/oidc/begin → { state, authUrl }
//   nav_to_swe          — page.goto(authUrl) → DOMContentLoaded
//   swe_form_fill       — locate username/password hosts + fill both
//   swe_sign_in_click   — locate Sign In trigger + click (form submit)
//   wait_for_callback   — wait for browser to land at /callback?code=...
//   oidc_await          — GET /warmup/oidc/await/:state → token bundle
//   total               — wall clock across oidc_begin .. oidc_await
//
// Returned IterationResult is JSONL-serializable (no functions, no
// Locators). The harness's /await response is consumed but discarded —
// we only care that it returned ok.
// ---------------------------------------------------------------------------

interface PhaseTimings {
  oidc_begin_ms?:        number;
  nav_to_swe_ms?:        number;
  swe_form_fill_ms?:     number;
  swe_sign_in_click_ms?: number;
  wait_for_callback_ms?: number;
  oidc_await_ms?:        number;
  total_ms:              number;
}

interface IterationResult {
  ts:        string;       // ISO timestamp of iteration START
  vu:        number;       // VU id (1-based)
  iter:      number;       // iteration ordinal for this VU
  userId:    string;
  ok:        boolean;
  phases:    PhaseTimings;
  failedAt?: keyof PhaseTimings | "setup"; // present when ok=false
  error?:    string | null;                 // brief, password-scrubbed
}

function now(): number { return performance.now(); }

// Strip a password from an error message before logging / persisting.
// Same policy as warmup/oidc.ts redact(): verbatim + URL-encoded, only
// if password is at least 3 chars (single-character passwords would
// over-match).
function redactPwd(s: string, password: string): string {
  if (!password || password.length < 3) return s;
  const enc = encodeURIComponent(password);
  return s.split(password).join("[REDACTED]").split(enc).join("[REDACTED]");
}

interface RunIterationArgs {
  vuId:            number;
  iter:            number;
  user:            LoadTestUser;
  context:         BrowserContext;
  harnessUrl:      string;
  callbackOrigin:  string;
  realm:           string;
}

async function runLoginIteration(args: RunIterationArgs): Promise<IterationResult> {
  const ts        = new Date().toISOString();
  const t0_total  = now();
  const phases: PhaseTimings = { total_ms: 0 };
  const result: IterationResult = {
    ts,
    vu:     args.vuId,
    iter:   args.iter,
    userId: args.user.userId,
    ok:     false,
    phases,
  };

  let page: Page | null = null;
  try {
    page = await args.context.newPage();
    page.setDefaultTimeout(ITER_NAV_TIMEOUT_MS);
    page.setDefaultNavigationTimeout(ITER_NAV_TIMEOUT_MS);

    // Install the realm-gated carve-out pump BEFORE the first navigation.
    // We reuse this rather than introducing a new code path that doesn't
    // install it because (a) the pump is realm-gated and a no-op for
    // realms outside ALLOWLIST_CARVE_OUT_REALMS, and (b) the brief
    // explicitly tells us not to bypass the gate. The pump's
    // success/failure does NOT affect the iteration result — we never
    // await its promise here. dispose() runs in `finally` to clear the
    // per-page state and reject any pending promise as "disposed".
    const pump = await installCarveOutPump(page, args.realm);
    // Always swallow the pump's promise — it's a no-op for the load test.
    pump.capturedPromise.catch(() => undefined);

    try {
      // Phase 1: /warmup/oidc/begin
      const tBegin0 = now();
      let begin;
      try {
        begin = await beginFlow(args.harnessUrl, args.user.userId);
      } catch (e) {
        phases.oidc_begin_ms = Math.round(now() - tBegin0);
        throw Object.assign(new Error((e as Error).message), { failedAt: "oidc_begin_ms" });
      }
      phases.oidc_begin_ms = Math.round(now() - tBegin0);

      // Phase 2: navigate to authorize URL → SWE login screen
      const tNav0 = now();
      try {
        await page.goto(begin.authUrl, { waitUntil: "domcontentloaded" });
      } catch (e) {
        phases.nav_to_swe_ms = Math.round(now() - tNav0);
        throw Object.assign(new Error((e as Error).message), { failedAt: "nav_to_swe_ms" });
      }
      phases.nav_to_swe_ms = Math.round(now() - tNav0);

      // Phase 3: fill username + password.
      // SECURITY: sweFormFill() is the sole egress for args.user.password.
      // We do not log the password here, in the redactPwd path, or in any
      // catch block.
      const tFill0 = now();
      let pwHost;
      try {
        pwHost = await sweFormFill(page, args.user, ITER_NAV_TIMEOUT_MS);
      } catch (e) {
        phases.swe_form_fill_ms = Math.round(now() - tFill0);
        throw Object.assign(new Error((e as Error).message), { failedAt: "swe_form_fill_ms" });
      }
      phases.swe_form_fill_ms = Math.round(now() - tFill0);

      // Phase 4: click Sign In.
      const tClick0 = now();
      try {
        await sweClickSignIn(page, pwHost, ITER_NAV_TIMEOUT_MS);
      } catch (e) {
        phases.swe_sign_in_click_ms = Math.round(now() - tClick0);
        throw Object.assign(new Error((e as Error).message), { failedAt: "swe_sign_in_click_ms" });
      }
      phases.swe_sign_in_click_ms = Math.round(now() - tClick0);

      // Phase 5: wait for the browser to land at /callback?code=... | error=...
      const tCb0 = now();
      try {
        await page.waitForURL(
          (url) =>
            url.origin === args.callbackOrigin &&
            url.pathname === "/callback" &&
            (url.searchParams.has("code") || url.searchParams.has("error")),
          { timeout: ITER_AWAIT_TIMEOUT_MS, waitUntil: "domcontentloaded" },
        );
      } catch (e) {
        phases.wait_for_callback_ms = Math.round(now() - tCb0);
        throw Object.assign(new Error((e as Error).message), { failedAt: "wait_for_callback_ms" });
      }
      phases.wait_for_callback_ms = Math.round(now() - tCb0);

      // Phase 6: harness long-poll → token bundle. We discard the body
      // (we don't need doken, refreshToken, or any carve-out fields) —
      // success of this phase is the contract that login completed.
      const tAw0 = now();
      try {
        const awaitResp = await awaitFlow(args.harnessUrl, begin.state, ITER_AWAIT_TIMEOUT_MS);
        if (!awaitResp.doken) {
          throw new Error("await flow returned ok but no doken field");
        }
      } catch (e) {
        phases.oidc_await_ms = Math.round(now() - tAw0);
        throw Object.assign(new Error((e as Error).message), { failedAt: "oidc_await_ms" });
      }
      phases.oidc_await_ms = Math.round(now() - tAw0);

      result.ok = true;
    } finally {
      pump.dispose();
    }
  } catch (e) {
    result.ok = false;
    const failedAt = (e as { failedAt?: keyof PhaseTimings }).failedAt;
    result.failedAt = failedAt ?? "setup";
    const raw = e instanceof Error ? e.message : String(e);
    result.error = redactPwd(raw, args.user.password);
  } finally {
    if (page) {
      await page.close().catch(() => undefined);
    }
    phases.total_ms = Math.round(now() - t0_total);
  }

  return result;
}

// ---------------------------------------------------------------------------
// JSONL sink — one line per completed iteration.
//
// We use fs.openSync + writeSync (no streams) because each writeSync of
// a buffer < PIPE_BUF (4 KiB on Linux) is atomic against concurrent
// writers in the same process. Iteration JSON lines fit comfortably
// (well under 1 KiB even with stack traces).
// ---------------------------------------------------------------------------

class JsonlSink {
  private fd: number | null = null;
  private path: string;
  private rowCount = 0;
  constructor(path: string) {
    this.path = path;
  }
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

// Nearest-rank percentile — adequate for load-test summary stats; we
// don't need interpolation precision here.
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
    harnessUrl:        string;
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
  for (const r of rows) {
    if (r.ok) continue;
    const k = r.failedAt ?? "unknown";
    failuresByPhase[k] = (failuresByPhase[k] ?? 0) + 1;
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
  };
}

// ---------------------------------------------------------------------------
// VU loop + ramp scheduler
// ---------------------------------------------------------------------------

interface RunCtx {
  browser:         Browser;
  pool:            UserPool;
  harnessUrl:      string;
  callbackOrigin:  string;
  realm:           string;
  deadlineMs:      number;
  sink:            JsonlSink;
  // Mutable concurrency counters (single-threaded — JS event loop, no race).
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
      // Fresh BrowserContext per iteration = fresh cookie jar (matches
      // the warm-up's per-user isolation).
      const context = await ctx.browser.newContext();
      let row: IterationResult;
      try {
        row = await runLoginIteration({
          vuId,
          iter,
          user,
          context,
          harnessUrl:     ctx.harnessUrl,
          callbackOrigin: ctx.callbackOrigin,
          realm:          ctx.realm,
        });
      } catch (e) {
        // runLoginIteration is designed to never throw — but cover the
        // edge cases (e.g. browser.newContext throwing) defensively.
        row = {
          ts:       new Date().toISOString(),
          vu:       vuId,
          iter,
          userId:   user.userId,
          ok:       false,
          phases:   { total_ms: 0 },
          failedAt: "setup",
          error:    redactPwd((e as Error).message, user.password),
        };
      } finally {
        await context.close().catch(() => undefined);
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

// Spawns VUs over the ramp window. Returns a promise that resolves
// after every VU's loop has exited.
async function scheduleVUs(ctx: RunCtx, concurrency: number, rampS: number): Promise<void> {
  const spawnGapMs = concurrency <= 1 ? 0 : Math.round((rampS * 1000) / concurrency);
  const vuPromises: Promise<void>[] = [];
  for (let k = 0; k < concurrency; k++) {
    if (k > 0 && spawnGapMs > 0) {
      // If the deadline has already passed during ramp, stop spawning.
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
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<number> {
  const startedAt = new Date().toISOString();
  const startedMonotonic = Date.now();

  logInfo(
    `config: concurrency=${CONCURRENCY} ramp=${RAMP_S}s duration=${DURATION_S}s ` +
      `harnessUrl=${HARNESS_URL} resultsPath=${RESULTS_PATH}`,
  );

  // 1. Users + harness health.
  let users: LoadTestUser[];
  try {
    users = loadUsers(USERS_PATH);
  } catch (e) {
    logError((e as Error).message);
    return 1;
  }
  logInfo(`loaded ${users.length} user(s) from ${USERS_PATH}`);

  let health: HarnessHealth;
  try {
    health = await fetchHarnessHealth(HARNESS_URL);
  } catch (e) {
    logError((e as Error).message);
    return 1;
  }
  logInfo(
    `harness ok — tcBase=${health.tcBase} realm=${health.tcRealm} client=${health.oidcClientId}`,
  );

  let callbackOrigin: string;
  try {
    callbackOrigin = new URL(health.callbackUrl).origin;
  } catch {
    logError(`harness reported invalid callbackUrl=${health.callbackUrl}`);
    return 1;
  }

  // 2. Realm bootstrap (fail-fast on a totally broken realm).
  try {
    const bootstrap = await bootstrapRealmFixture({
      tcBase:   health.tcBase,
      tcRealm:  health.tcRealm,
      homeOrkUrl: HOME_ORK_URL,
      fallback: FALLBACK_REALM,
    });
    logInfo(
      `realm bootstrap OK — orks=${bootstrap.realm.orks.length} pathUsed=${bootstrap.pathUsed}`,
    );
  } catch (e) {
    logError(`realm bootstrap failed: ${(e as Error).message}`);
    return 1;
  }

  // 3. Sink + Playwright.
  const sink = new JsonlSink(RESULTS_PATH);
  try {
    sink.open();
  } catch (e) {
    logError(`failed to open results sink at ${RESULTS_PATH}: ${(e as Error).message}`);
    return 1;
  }
  logInfo(`writing JSONL to ${sink.filePath()}`);

  let browser: Browser;
  try {
    browser = await chromium.launch({ headless: HEADLESS });
  } catch (e) {
    logError(
      `playwright failed to launch chromium: ${(e as Error).message}. ` +
        `Hint: run \`npx playwright install chromium\` once on this host.`,
    );
    sink.close();
    return 1;
  }

  // 4. Run the test.
  const deadlineMs = startedMonotonic + (RAMP_S + DURATION_S) * 1000;
  const ctx: RunCtx = {
    browser,
    pool:            new UserPool(users),
    harnessUrl:      HARNESS_URL,
    callbackOrigin,
    realm:           health.tcRealm,
    deadlineMs,
    sink,
    activeVUs:       { value: 0 },
    peakConcurrency: { value: 0 },
  };

  // Light periodic heartbeat so the operator sees progress.
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
    await browser.close().catch(() => undefined);
    sink.close();
  }

  // 5. Summary.
  const endedAt = new Date().toISOString();
  let rows: IterationResult[] = [];
  try {
    // Re-read the JSONL we just wrote rather than holding everything in
    // memory — the file IS the source of truth, and this naturally
    // matches what an offline analyser would see.
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
      harnessUrl:    HARNESS_URL,
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
