//
// Single-flow smoke CLI for the protocol module.
//
// Reads:
//   LOAD_TEST_USERS_PATH (default ./load-test-users.json) — same file as the warm-up.
//   TIDECLOAK_BASE_URL                                    — e.g. https://staging.dauth.me
//   TIDECLOAK_REALM                                       — e.g. tide-metrics-load
//   OIDC_CLIENT_ID                                        — e.g. tide-loadtest-harness
//   OIDC_REDIRECT_URI  (optional)                         — defaults to http://localhost:3000/callback
//                                                           (matches server.ts default; for R3 the
//                                                            redirect target is never followed)
//
// Picks user[0] from the users file and runs NodeCmkClient.login()
// exactly once. Prints the result JSON. Useful both as a smoke test
// after `npm run build` and as the seed for the multi-VU R5 driver.
//
// SECURITY: prints userId verbatim (operator-visible only). Never
// prints the password, even on failure (NodeCmkClient already redacts).
//

import "./undici-setup.js";
import { readFileSync } from "node:fs";

import { NodeCmkClient } from "./nodeCmkClient.js";
import type { LoadTestUser, LoadTestUsersFile } from "../warmup/types.js";
import type { RealmFixture } from "../runSign.js";

const USERS_PATH    = process.env.LOAD_TEST_USERS_PATH ?? "./load-test-users.json";
const TC_BASE       = (process.env.TIDECLOAK_BASE_URL ?? "https://staging.dauth.me").replace(/\/+$/, "");
const TC_REALM      = process.env.TIDECLOAK_REALM     ?? "tide-metrics-load";
const OIDC_CLIENT   = process.env.OIDC_CLIENT_ID      ?? "tide-loadtest-harness";
const CALLBACK_URL  = process.env.OIDC_REDIRECT_URI   ?? "http://localhost:3000/callback";
// R4: required for the crypto fan-out (NetworkClient.GetKeyInfo lives on
// the home ORK). Same env var the warm-up uses.
const HOME_ORK_URL  = (process.env.WARMUP_HOME_ORK    ?? "https://sork1.tideprotocol.com").replace(/\/+$/, "");

function loadFirstUser(path: string): LoadTestUser {
  const raw = readFileSync(path, "utf8");
  const parsed = JSON.parse(raw) as LoadTestUsersFile;
  if (!parsed?.users?.length) {
    throw new Error(`users file ${path} has no users[]`);
  }
  const u = parsed.users[0];
  if (!u?.userId || !u?.password) {
    throw new Error(`users file ${path}: first entry missing userId or password`);
  }
  return u;
}

async function main(): Promise<number> {
  // eslint-disable-next-line no-console
  console.log(
    `[protocol-cli] tcBase=${TC_BASE} realm=${TC_REALM} client=${OIDC_CLIENT} callback=${CALLBACK_URL} homeOrk=${HOME_ORK_URL}`,
  );

  let user: LoadTestUser;
  try {
    user = loadFirstUser(USERS_PATH);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error(`[protocol-cli] FAILED to load user: ${(e as Error).message}`);
    return 1;
  }
  // eslint-disable-next-line no-console
  console.log(`[protocol-cli] using user.userId=${user.userId}`);

  // The RealmFixture is only used by NodeCmkClient for the diagnostic log
  // line at the end of login(). The crypto fan-out reads voucherURL,
  // authorizerPack, gVVK, sid, vRedirectUri straight off the SWE URL
  // captured in Fetch 1 — none of those need to be on the fixture. We
  // pass HOME_ORK_URL into NodeCmkClient directly (R4: needed for
  // NetworkClient.GetKeyInfo). orks[] is unused: dCMKPasswordFlow gets
  // its OrkInfo[] from KeyInfo, not the fixture.
  const realm: RealmFixture = {
    realm:       TC_REALM,
    vvkid:       "<protocol-cli-stub>",
    vvkPublic:   "<protocol-cli-stub>",
    voucherURL:  "<protocol-cli-stub>",
    homeOrkUrl:  HOME_ORK_URL,
    orks:        [],
  };

  const client = new NodeCmkClient({
    tcBase:      TC_BASE,
    tcRealm:     TC_REALM,
    clientId:    OIDC_CLIENT,
    callbackUrl: CALLBACK_URL,
    homeOrkUrl:  HOME_ORK_URL,
  });

  const result = await client.login(user, realm);

  // Redact the OIDC `code` for operator-visible output. R4 security audit:
  // we don't want a one-shot OIDC authorization code on a developer
  // terminal in case it's screen-shared/recorded. Same logic as the v1
  // harness applied to tokens. Shape (length + prefix) is preserved so
  // smoke-test debugging still works.
  const safeResult = result.code
    ? { ...result, code: `[REDACTED len=${result.code.length} sample=${result.code.slice(0, 8)}…]` }
    : result;
  // eslint-disable-next-line no-console
  console.log(`[protocol-cli] result:\n${JSON.stringify(safeResult, null, 2)}`);

  return result.ok ? 0 : 1;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    // eslint-disable-next-line no-console
    console.error(`[protocol-cli] fatal: ${(e as Error)?.stack ?? String(e)}`);
    process.exit(1);
  },
);
