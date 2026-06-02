//
// Playwright warm-up orchestrator (v1).
//
// Reads a list of test users from a JSON file, drives the SWE login
// flow once per user against a live TideCloak + sork stack, and writes
// fixtures.json with {schemaVersion, capturedAt, realm, users[]}.
//
// Inputs (all via env, all defaulted):
//   HARNESS_URL          — e.g. http://localhost:3000 (default)
//   LOAD_TEST_USERS_PATH — JSON file of {users:[{userId,password}]}
//                          (default: ./load-test-users.json)
//   FIXTURES_OUT_PATH    — output path (default: ./fixtures.json)
//   WARMUP_HEADLESS      — "false" to launch a visible browser for
//                          debugging (default: true)
//
// The driver also reads its realm config (tcBase, realm, homeOrkUrl)
// from the harness /health response, so the harness server is the
// single source of truth for which realm we're warming. The warm-up
// MUST be run against a harness configured for the same realm the
// load test will use.
//
// Exit codes:
//   0 — at least one user captured AND realm config captured
//   1 — zero users captured, OR realm config missing, OR fatal config error
//
import "../shims.js";
import { chromium, type Browser } from "playwright";
import { readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { bootstrapRealmFixture } from "./realm.js";
import { captureUserFixture } from "./oidc.js";
import type {
  HarnessHealth,
  LoadTestUser,
  LoadTestUsersFile,
} from "./types.js";
import type { RealmFixture, UserFixture } from "../runSign.js";

// Fallback realm values from a known-good staging capture.
//
// Round-5: vvkid/vvkPublic are NOT fetchable without admin auth (the
// /realms/{r}/keys path is admin-only; the public JWKS does not list
// tide-vendor-key). So we always seed them from this fallback — Path α
// in oidc.ts then patches the realm fixture in place from the first
// user's SWE URL (gVVK=…). Captured 2026-06-02 from tide-metrics-load
// on staging.dauth.me.
const FALLBACK_REALM: Partial<RealmFixture> = {
  vvkid:     "e683904fedb0c52e5a04c41e005df373f9fce407b6d436f750d489672c0cbc6b",
  vvkPublic: "e683904fedb0c52e5a04c41e005df373f9fce407b6d436f750d489672c0cbc6b",
};

const HARNESS_URL = (process.env.HARNESS_URL ?? "http://localhost:3000").replace(/\/+$/, "");
const USERS_PATH = process.env.LOAD_TEST_USERS_PATH ?? "./load-test-users.json";
const OUT_PATH = process.env.FIXTURES_OUT_PATH ?? "./fixtures.json";
const HEADLESS = (process.env.WARMUP_HEADLESS ?? "true").toLowerCase() !== "false";

declare const fetch: typeof globalThis.fetch;

function logInfo(msg: string): void {
  // eslint-disable-next-line no-console
  console.log(`[warmup] ${msg}`);
}
function logWarn(msg: string): void {
  // eslint-disable-next-line no-console
  console.warn(`[warmup] WARN ${msg}`);
}
function logError(msg: string): void {
  // eslint-disable-next-line no-console
  console.error(`[warmup] ERROR ${msg}`);
}

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

interface AtomicWriteOpts {
  outPath:  string;
  realm:    RealmFixture;
  users:    UserFixture[];
  tmpExt?:  string;
}

function atomicWriteFixtures({ outPath, realm, users, tmpExt = ".tmp" }: AtomicWriteOpts): string {
  const abs = resolvePath(outPath);
  const tmp = `${abs}${tmpExt}`;
  mkdirSync(dirname(abs), { recursive: true });
  const blob = {
    schemaVersion: "1" as const,
    capturedAt:    new Date().toISOString(),
    realm,
    users,
  };
  writeFileSync(tmp, JSON.stringify(blob, null, 2));
  renameSync(tmp, abs);
  return abs;
}

async function main(): Promise<number> {
  // 1. Load users from disk.
  let users: LoadTestUser[];
  try {
    users = loadUsers(USERS_PATH);
  } catch (e) {
    logError((e as Error).message);
    return 1;
  }
  logInfo(`loaded ${users.length} user(s) from ${USERS_PATH}`);

  // 2. Verify harness reachable and read its realm config.
  let health: HarnessHealth;
  try {
    health = await fetchHarnessHealth(HARNESS_URL);
  } catch (e) {
    logError((e as Error).message);
    return 1;
  }
  logInfo(
    `harness ok — tcBase=${health.tcBase} realm=${health.tcRealm} client=${health.oidcClientId} callbackUrl=${health.callbackUrl}`,
  );

  // The callbackOrigin we wait for is derived from health.callbackUrl so
  // a misconfigured harness (e.g. running on a different port) is
  // detected by the oidc.ts waitForURL predicate rather than silently
  // hanging the warm-up.
  let callbackOrigin: string;
  try {
    callbackOrigin = new URL(health.callbackUrl).origin;
  } catch {
    logError(`harness reported invalid callbackUrl=${health.callbackUrl}`);
    return 1;
  }

  // 3. Bootstrap the realm fixture (Path β, fallback to sample on miss).
  //    The home-ork URL is hardcoded for staging unless overridden.
  const homeOrkUrl = (process.env.WARMUP_HOME_ORK ?? "https://sork1.tideprotocol.com").replace(
    /\/+$/,
    "",
  );
  let realm: RealmFixture;
  let vvkidStartedAsFallback = false;
  let voucherUrlStartedAsFallback = false;
  try {
    const bootstrap = await bootstrapRealmFixture({
      tcBase:     health.tcBase,
      tcRealm:    health.tcRealm,
      homeOrkUrl,
      fallback:   FALLBACK_REALM,
    });
    realm = bootstrap.realm;
    vvkidStartedAsFallback = bootstrap.vvkidFromFallback;
    voucherUrlStartedAsFallback = bootstrap.voucherUrlFromFallback;
    for (const note of bootstrap.notes) {
      logInfo(`  • ${note}`);
    }
    // Round-5 single-line bootstrap marker the operator greps for.
    const orksMode    = `${realm.orks.length} (live)`;
    const vvkMode     = vvkidStartedAsFallback ? "fallback" : "empty";
    const voucherMode = voucherUrlStartedAsFallback ? "fallback" : "synth";
    logInfo(
      `realm bootstrap OK — orks=${orksMode} vvk=${vvkMode} voucherURL=${voucherMode} pathUsed=${bootstrap.pathUsed}`,
    );
  } catch (e) {
    logError(`realm bootstrap failed: ${(e as Error).message}`);
    return 1;
  }

  // 4. Launch Playwright once for the whole warm-up. We use a fresh
  //    BrowserContext per user so cookies / storage are isolated.
  let browser: Browser;
  try {
    browser = await chromium.launch({ headless: HEADLESS });
  } catch (e) {
    logError(
      `playwright failed to launch chromium: ${(e as Error).message}. ` +
        `Hint: run \`npx playwright install chromium\` once on this host.`,
    );
    return 1;
  }

  // 5. Per-user loop.
  const captured: UserFixture[] = [];
  const failures: { userId: string; reason: string }[] = [];

  // Path-α sniffer: opportunistically patch realm-level fields from the
  // first user's SWE URL. The SWE URL carries `gVVK=<hex>` (the
  // canonical vvkid/vvkPublic for the realm — they're hex-equal per
  // SERIALIZATION-NOTES.md) and `voucherURL=<urlencoded>` (the realm-
  // stable voucher pattern including the per-realm clientId). We listen
  // for the first URL across all users that has any of these params;
  // once we've patched a field we don't overwrite it.
  let alphaPatchedVvk = false;
  let alphaPatchedVoucher = false;
  const onSweUrl = (url: string) => {
    try {
      const u = new URL(url);
      // Patch vvkid/vvkPublic from gVVK=.
      if (!alphaPatchedVvk) {
        const gvvk = u.searchParams.get("gVVK");
        if (gvvk && /^[0-9a-fA-F]+$/.test(gvvk)) {
          const prior = realm.vvkid;
          realm.vvkid     = gvvk;
          realm.vvkPublic = gvvk;
          alphaPatchedVvk = true;
          const priorTag = prior
            ? (prior === gvvk ? "unchanged" : `was ${prior.slice(0, 12)}…`)
            : "was empty";
          logInfo(
            `realm patched from SWE URL — vvkid=${gvvk.slice(0, 12)}… (${priorTag})`,
          );
        }
      }
      // Patch voucherURL pattern from voucherURL=.
      if (!alphaPatchedVoucher) {
        const voucher = u.searchParams.get("voucherURL");
        if (voucher) {
          const decoded = decodeURIComponent(voucher);
          // Replace the per-session bits with placeholders so the pattern
          // is reusable for every iteration of runSign().
          const patterned = decoded
            .replace(/(\bsessionId=)[^&]*/i, "$1<PER_SESSION>")
            .replace(/(\btabId=)[^&]*/i, "$1<PER_TAB>");
          realm.voucherURL = patterned;
          alphaPatchedVoucher = true;
          // Surface just the host+path so we don't echo session bits to
          // the log even though we've already replaced them.
          let pattern = patterned;
          try {
            const pu = new URL(patterned);
            pattern = `${pu.origin}${pu.pathname}`;
          } catch {
            // not a full URL — log as-is (already pattern-scrubbed).
          }
          logInfo(
            `realm patched from SWE URL — voucherURL=${pattern}`,
          );
        }
      }
    } catch {
      // best-effort — Path α must not break the warm-up.
    }
  };

  for (let i = 0; i < users.length; i++) {
    const user = users[i];
    logInfo(`[${i + 1}/${users.length}] capturing ${user.userId} …`);
    const context = await browser.newContext();
    try {
      const fixture = await captureUserFixture({
        harnessUrl:     HARNESS_URL,
        callbackOrigin,
        user,
        context,
        // realm gates the Option B sessKey carve-out (see oidc.ts
        // ALLOWLIST_CARVE_OUT_REALMS). Sourced from /health so the
        // capture decision tracks whatever the harness server is
        // configured for — no env override.
        realm:          health.tcRealm,
        onSweUrl,
      });
      captured.push(fixture);
      logInfo(`[${i + 1}/${users.length}] ok userId=${fixture.userId} vuid=${fixture.vuid.slice(0, 12)}…`);
    } catch (e) {
      const msg = (e as Error).message;
      failures.push({ userId: user.userId, reason: msg });
      logWarn(`[${i + 1}/${users.length}] FAILED ${user.userId}: ${msg}`);
      // Continue to next user — per-user failures must NOT abort the
      // whole warm-up. (See Round-3 brief: bad-creds / captcha / timeout
      // is logged + skipped.)
    } finally {
      await context.close().catch(() => {});
    }
  }

  await browser.close().catch(() => {});

  // 6. Decide success / failure.
  if (captured.length === 0) {
    logError(
      `0 users captured; ${failures.length} failed. Not writing fixtures.json. ` +
        `First failure: ${failures[0]?.reason ?? "(none)"}`,
    );
    return 1;
  }

  // 7. Write fixtures.json atomically.
  const outAbs = atomicWriteFixtures({ outPath: OUT_PATH, realm, users: captured });
  logInfo(
    `wrote ${captured.length}/${users.length} fixtures to ${outAbs} ` +
      `(${failures.length} failed)`,
  );
  if (failures.length > 0) {
    for (const f of failures) {
      logWarn(`  skipped ${f.userId}: ${f.reason}`);
    }
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
