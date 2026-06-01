//
// Playwright warm-up orchestrator (STUB for v1).
//
// Spawns a headless Chromium, drives the SWE sign-up + login flow for
// N test users against a staging realm, and captures the resulting
// per-user state (Doken + sessKey + VVK + ORK list) into fixtures.json
// for the load harness server to replay under load.
//
// v1 status: scaffolded only. The real flow needs iterative work with
// QA against the live SWE — out of scope for the skeleton PR. Running
// `npm run warmup` today fails fast inside enrollOne() rather than
// silently producing an empty fixture file.
//
import "../shims.js";
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";
import type { UserFixture } from "../runSign.js";

const STAGING_BASE = process.env.STAGING_BASE ?? "https://staging.dauth.me";
const REALM = process.env.WARMUP_REALM ?? "tide-metrics-load";
const N = Number(process.env.WARMUP_USERS ?? 5);

async function enrollOne(idx: number): Promise<UserFixture> {
  // TODO(v1.1): drive the real SWE enrollment flow with Playwright.
  //
  // Outline:
  //   1. chromium.launch({ headless: true }) → newContext() → newPage()
  //   2. page.goto(`${STAGING_BASE}/realms/${REALM}/account`)
  //   3. Click "Sign in with Tide" → drive the SWE sign-up sub-flow
  //      (CMK keygen happens client-side; the master ORK SubmitUser
  //      call happens transparently inside the SWE iframe).
  //   4. After login, capture from the page's localStorage / sessionStorage:
  //        - The Doken (and its serialization format — this is one of
  //          the v1.1 unknowns).
  //        - The sessKey (TideKey serialization — also v1.1 unknown).
  //        - vvkid + vvkPublic + ORK list + voucherURL + homeOrkUrl.
  //   5. Shape into a UserFixture and return.
  //
  // For v1 skeleton: throw clearly so the harness fails fast if anyone
  // runs `npm run warmup` before the real flow is wired up.

  // Touch chromium so tsc keeps the playwright dep import "live" — the
  // real wiring will use it; the stub doesn't.
  void chromium;

  throw new Error(
    `TODO(v1.1): implement Playwright enrollment for user ${idx}. ` +
      `Drive: ${STAGING_BASE}/realms/${REALM}/account → "Sign in with Tide" → sign-up flow.`,
  );
}

async function main() {
  const users: UserFixture[] = [];
  for (let i = 0; i < N; i++) {
    const u = await enrollOne(i);
    users.push(u);
    console.log(`enrolled ${i + 1}/${N}: ${u.userId}`);
  }

  const out = {
    schemaVersion: "1" as const,
    realm: REALM,
    createdAt: new Date().toISOString(),
    users,
  };
  writeFileSync("./fixtures.json", JSON.stringify(out, null, 2));
  console.log(`wrote ${users.length} fixtures to ./fixtures.json`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
