//
// Bulk user provisioner — drive the SWE Sign-Up flow for users
// metrics-load-NNN where NNN ∈ [START_INDEX, END_INDEX].
//
// Behaviour:
//   * Shared password sourced from load-test-users.json user[0]. Never
//     hard-coded, never logged.
//   * Idempotency: probes the home ORK at GetReservers/<sha256(userId)>
//     to detect users that already exist in the cohort. 200 → exists,
//     skip. 404/4xx → not present, attempt provisioning. (Admin REST
//     /users?username= probe would be ideal but requires admin auth;
//     the cohort probe gives equivalent precision without it.)
//   * Per-user pipeline:
//       1. Cohort presence probe → skip if 200.
//       2. Sign-Up driver (drive SWE step1+step2 → first-broker-login →
//          /callback). Captures voucher and cohort-convert counts.
//       3. Verification: NodeCmkClient.login() against the new user.
//       4. On success: append to load-test-users.json atomically.
//   * Per-user failures are logged and DO NOT abort the run.
//   * After every user the loop prints a one-line marker for the
//     operator (no IGA change-request queue check — observed during
//     Phase 1 that Sign-Up does NOT create IGA drafts; the IGA gate is
//     hit later at token-exchange (R19 NO_USER_CONTEXT) which the load
//     test doesn't exercise).
//   * After all attempts: prints a summary.
//
// Env vars:
//   HARNESS_URL          (default http://localhost:3000)
//   START_INDEX          (default 2)
//   END_INDEX            (default 31)   — inclusive
//   USERNAME_PREFIX      (default "metrics-load-")
//   EMAIL_DOMAIN         (default "invalid.tide.test")
//   LOAD_TEST_USERS_PATH (default ./load-test-users.json)
//   TIDECLOAK_BASE_URL   (default https://staging.dauth.me)
//   TIDECLOAK_REALM      (default tide-metrics-load)
//   OIDC_CLIENT_ID       (default tide-loadtest-harness)
//   OIDC_REDIRECT_URI    (default http://localhost:3000/callback)
//   WARMUP_HOME_ORK      (default https://sork1.tideprotocol.com)
//   PROVISION_HEADLESS   (default true)
//

import { chromium, type Browser } from "playwright";
import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { createHash, randomBytes } from "node:crypto";

import { driveSignUpFlow } from "./signupFlow.js";
import { NodeCmkClient } from "../protocol/nodeCmkClient.js";
import type { LoadTestUser, LoadTestUsersFile } from "../warmup/types.js";
import type { RealmFixture } from "../runSign.js";

declare const fetch: typeof globalThis.fetch;

const HARNESS_URL = (process.env.HARNESS_URL ?? "http://localhost:3000").replace(/\/+$/, "");
const TC_BASE     = (process.env.TIDECLOAK_BASE_URL ?? "https://staging.dauth.me").replace(/\/+$/, "");
const TC_REALM    = process.env.TIDECLOAK_REALM     ?? "tide-metrics-load";
const OIDC_CLIENT = process.env.OIDC_CLIENT_ID      ?? "tide-loadtest-harness";
const CALLBACK_URL = process.env.OIDC_REDIRECT_URI  ?? `${HARNESS_URL}/callback`;
const HOME_ORK    = (process.env.WARMUP_HOME_ORK    ?? "https://sork1.tideprotocol.com").replace(/\/+$/, "");
const USERS_PATH  = process.env.LOAD_TEST_USERS_PATH ?? "./load-test-users.json";
const USERNAME_PREFIX = process.env.USERNAME_PREFIX ?? "metrics-load-";
const EMAIL_DOMAIN    = process.env.EMAIL_DOMAIN    ?? "invalid.tide.test";
const START_INDEX = Math.max(1, parseInt(process.env.START_INDEX ?? "2",  10));
const END_INDEX   = Math.max(START_INDEX, parseInt(process.env.END_INDEX ?? "31", 10));
const HEADLESS    = (process.env.PROVISION_HEADLESS ?? "true").toLowerCase() !== "false";

function log(msg: string): void {
  // eslint-disable-next-line no-console
  console.log(`[provision] ${msg}`);
}
function logWarn(msg: string): void {
  // eslint-disable-next-line no-console
  console.warn(`[provision] WARN ${msg}`);
}
function logError(msg: string): void {
  // eslint-disable-next-line no-console
  console.error(`[provision] ERROR ${msg}`);
}

function pad3(n: number): string {
  return n.toString().padStart(3, "0");
}

function userIdFor(n: number): string {
  return `${USERNAME_PREFIX}${pad3(n)}`;
}

function emailFor(n: number): string {
  return `${USERNAME_PREFIX}${pad3(n)}@${EMAIL_DOMAIN}`;
}

// SHA256 hex of input (matches Cryptide.Serialization.GetUID hex form).
function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

interface UsersFileBlob extends LoadTestUsersFile {}

function readUsersFile(path: string): UsersFileBlob {
  const raw = readFileSync(path, "utf8");
  const parsed = JSON.parse(raw) as UsersFileBlob;
  if (!parsed?.users || !Array.isArray(parsed.users)) {
    throw new Error(`users file ${path} has no users[]`);
  }
  return parsed;
}

function atomicWriteUsersFile(path: string, blob: UsersFileBlob): void {
  const abs = resolvePath(path);
  const tmp = `${abs}.tmp`;
  mkdirSync(dirname(abs), { recursive: true });
  writeFileSync(tmp, JSON.stringify({ users: blob.users }, null, 2));
  renameSync(tmp, abs);
}

interface BeginResp { ok: boolean; state: string; authUrl: string }

async function beginOidcFlow(userId: string): Promise<BeginResp> {
  const res = await fetch(`${HARNESS_URL}/warmup/oidc/begin`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ userId }),
  });
  if (!res.ok) throw new Error(`begin ${res.status}`);
  return res.json() as Promise<BeginResp>;
}

// Lightweight existence check.
//
// Originally we probed `GetReservers/<vuid>` on the home ORK to detect
// already-provisioned users. That endpoint turned out to be side-effecting
// (it issues a reservation on a fresh vuid; SWE Sign-Up calls it as step 1
// of dKeyGenerationFlow). Probing externally before driving Sign-Up either
// (a) consumes a reservation slot the upcoming Sign-Up would have used, or
// (b) returns 409 because a prior probe of ours already reserved it. Both
// outcomes are bad.
//
// Instead, we rely on:
//   1. The local load-test-users.json: already-tracked users get skipped
//      directly without any network call (handled by main()).
//   2. The Sign-Up flow itself: if a user is partially / fully present on
//      TideCloak we'll surface a clear sign-up error (the SWE step 1 form
//      submission fails fast with a known marker we can classify).
//
// `metrics-load-001` and the probe-leftovers (`metrics-load-002`,
// `metrics-load-003`) are pre-seeded into load-test-users.json before
// the bulk run so they are skipped via path (1).
async function probeUserExists(_userId: string): Promise<"exists" | "absent" | "unknown"> {
  // Intentionally no-op. See comment above.
  return "unknown";
}

interface PerUserOutcome {
  userId:       string;
  index:        number;
  status:       "succeeded" | "skipped-exists" | "failed-signup" | "failed-verify";
  signUpStep?:  string;
  signUpError?: string;
  signUpMs?:    number;
  voucherDraws?: number;
  cohortConvertCount?: number;
  verifyMs?:    number;
  verifyError?: string;
}

async function provisionOne(
  browser: Browser,
  n: number,
  password: string,
): Promise<PerUserOutcome> {
  const userId = userIdFor(n);
  const email  = emailFor(n);
  const outcome: PerUserOutcome = { userId, index: n, status: "failed-signup" };

  // Idempotency is handled by the caller (users-file presence check); we
  // do not network-probe the cohort because GetReservers/<vuid> has side
  // effects. See probeUserExists() docstring.
  void probeUserExists;

  // 2. Begin OIDC flow on the harness for this user.
  let begin: BeginResp;
  try {
    begin = await beginOidcFlow(userId);
  } catch (e) {
    outcome.signUpError = `begin: ${(e as Error).message}`;
    return outcome;
  }

  // 3. Sign-Up Playwright flow.
  const context = await browser.newContext();
  try {
    const signUp = await driveSignUpFlow({
      context,
      authUrl:        begin.authUrl,
      callbackOrigin: HARNESS_URL,
      user:           { userId, password },
      email,
      log:            (m) => log(`[${pad3(n)}] signup: ${m}`),
    });
    outcome.signUpStep         = signUp.step;
    outcome.signUpMs           = signUp.durationMs;
    outcome.voucherDraws       = signUp.voucherDraws;
    outcome.cohortConvertCount = signUp.cohortConvertCount;
    if (!signUp.ok) {
      outcome.signUpError = signUp.errorMessage ?? "unknown sign-up failure";
      return outcome;
    }
    log(
      `[${pad3(n)}] signup ok step=${signUp.step} ms=${signUp.durationMs} ` +
      `vouchers=${signUp.voucherDraws} cohortConvert=${signUp.cohortConvertCount} ` +
      `email=${email}`,
    );
  } finally {
    await context.close().catch(() => undefined);
  }

  // 4. Verify via NodeCmkClient.login.
  const client = new NodeCmkClient({
    tcBase:      TC_BASE,
    tcRealm:     TC_REALM,
    clientId:    OIDC_CLIENT,
    callbackUrl: CALLBACK_URL,
    homeOrkUrl:  HOME_ORK,
  });
  const realm: RealmFixture = {
    realm:      TC_REALM,
    vvkid:      "<provision-stub>",
    vvkPublic:  "<provision-stub>",
    voucherURL: "<provision-stub>",
    homeOrkUrl: HOME_ORK,
    orks:       [],
  };
  const verifyStart = Date.now();
  const result = await client.login({ userId, password }, realm);
  outcome.verifyMs = Date.now() - verifyStart;
  if (!result.ok) {
    outcome.status = "failed-verify";
    outcome.verifyError = (result.message ?? "unknown").slice(0, 400);
    return outcome;
  }
  outcome.status = "succeeded";
  log(`[${pad3(n)}] verify ok in ${outcome.verifyMs}ms`);
  return outcome;
}

async function main(): Promise<number> {
  log(
    `config: range=[${START_INDEX}..${END_INDEX}] prefix=${USERNAME_PREFIX} ` +
    `emailDomain=${EMAIL_DOMAIN} tcBase=${TC_BASE} realm=${TC_REALM} client=${OIDC_CLIENT} ` +
    `homeOrk=${HOME_ORK} headless=${HEADLESS} usersPath=${USERS_PATH}`,
  );

  // Verify harness reachable (for /warmup/oidc/begin and /callback).
  try {
    const h = await fetch(`${HARNESS_URL}/health`);
    if (!h.ok) throw new Error(`status ${h.status}`);
    const j = await h.json() as { tcRealm?: string };
    if (j.tcRealm && j.tcRealm !== TC_REALM) {
      logWarn(`harness configured for realm=${j.tcRealm}, this provisioner is for ${TC_REALM}. Continuing.`);
    }
  } catch (e) {
    logError(`harness at ${HARNESS_URL}/health not reachable: ${(e as Error).message}`);
    return 1;
  }

  // Load users file; extract the shared password from user[0].
  let blob: UsersFileBlob;
  try {
    blob = readUsersFile(USERS_PATH);
  } catch (e) {
    logError(`failed to read ${USERS_PATH}: ${(e as Error).message}`);
    return 1;
  }
  const u0: LoadTestUser | undefined = blob.users[0];
  if (!u0?.password) {
    logError(`${USERS_PATH} user[0] missing password`);
    return 1;
  }
  const password = u0.password;
  log(`shared password loaded from user[0] (length=${password.length}, value not logged)`);

  // Build existing-userId set for fast skip + append-only semantics.
  const existing = new Set(blob.users.map((u) => u.userId));

  let browser: Browser;
  try {
    browser = await chromium.launch({ headless: HEADLESS });
  } catch (e) {
    logError(`playwright failed to launch chromium: ${(e as Error).message}. ` +
      `Hint: run \`npx playwright install chromium\` once.`);
    return 1;
  }

  const outcomes: PerUserOutcome[] = [];
  let runCounter = 0;
  try {
    for (let n = START_INDEX; n <= END_INDEX; n++) {
      runCounter++;
      const userId = userIdFor(n);
      if (existing.has(userId)) {
        log(`[${pad3(n)}] already in load-test-users.json — skipping`);
        outcomes.push({ userId, index: n, status: "skipped-exists" });
        continue;
      }
      log(`---`);
      log(`[${pad3(n)}] starting ${userId}…`);
      let outcome: PerUserOutcome;
      try {
        outcome = await provisionOne(browser, n, password);
      } catch (e) {
        outcome = {
          userId,
          index: n,
          status: "failed-signup",
          signUpError: `unhandled: ${(e as Error).message?.slice(0, 300)}`,
        };
      }
      outcomes.push(outcome);
      log(`[${pad3(n)}] result: ${outcome.status} ` +
        `${outcome.signUpStep ? `step=${outcome.signUpStep} ` : ""}` +
        `${outcome.signUpError ? `err=${outcome.signUpError.slice(0, 200)}` : ""}` +
        `${outcome.verifyError ? `verifyErr=${outcome.verifyError.slice(0, 200)}` : ""}`);

      // Append to users file on success — atomically.
      if (outcome.status === "succeeded") {
        try {
          blob.users.push({ userId, password });
          atomicWriteUsersFile(USERS_PATH, blob);
          existing.add(userId);
          log(`[${pad3(n)}] appended to ${USERS_PATH} (total users=${blob.users.length})`);
        } catch (e) {
          logError(`[${pad3(n)}] FAILED to write users file: ${(e as Error).message}`);
          // Roll back in-memory.
          blob.users.pop();
        }
      }

      // Reminder about IGA: load-test brief expected drafts; Phase 1 probe
      // showed Sign-Up does NOT create IGA drafts. The R19 gate is
      // post-token-exchange. We surface this once at the start; no per-
      // user check needed.
      if (runCounter === 1) {
        log(`(IGA: Phase 1 probe showed Sign-Up does NOT enqueue IGA drafts — ` +
          `the R19 NO_USER_CONTEXT gate is hit later at /token, outside this flow.)`);
      }
    }
  } finally {
    await browser.close().catch(() => undefined);
  }

  // Summary.
  log(`---`);
  log(`summary:`);
  const counts = {
    succeeded: outcomes.filter(o => o.status === "succeeded").length,
    skipped:   outcomes.filter(o => o.status === "skipped-exists").length,
    failedSignup: outcomes.filter(o => o.status === "failed-signup").length,
    failedVerify: outcomes.filter(o => o.status === "failed-verify").length,
  };
  log(`  succeeded:     ${counts.succeeded}`);
  log(`  skipped-exists:${counts.skipped}`);
  log(`  failed-signup: ${counts.failedSignup}`);
  log(`  failed-verify: ${counts.failedVerify}`);
  const totalVouchers = outcomes
    .filter(o => typeof o.voucherDraws === "number")
    .reduce((a, o) => a + (o.voucherDraws ?? 0), 0);
  log(`  total voucher draws observed: ${totalVouchers}`);
  log(`  users file now at: ${USERS_PATH} (users.length=${blob.users.length})`);

  // Print failures for visibility.
  for (const o of outcomes) {
    if (o.status === "failed-signup" || o.status === "failed-verify") {
      logWarn(`  ${o.userId} (${o.status}) step=${o.signUpStep ?? ""} ` +
        `err=${(o.signUpError ?? o.verifyError ?? "").slice(0, 250)}`);
    }
  }

  return counts.succeeded + counts.skipped > 0 ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    logError(`fatal: ${(e as Error)?.stack ?? String(e)}`);
    process.exit(1);
  },
);
