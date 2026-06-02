//
// Local types for the warm-up driver. Public schema types
// (UserFixture / RealmFixture / OrkInfo) live in ../runSign.ts and are
// imported by the warm-up code from there so the on-disk shape stays
// single-sourced.
//

// Shape of the input file at LOAD_TEST_USERS_PATH.
//
// Passwords stay in this file (which is git-ignored / operator-managed)
// and never get hard-coded into source. The warm-up reads it and
// forwards each (userId, password) into the per-user OIDC flow.
export interface LoadTestUser {
  userId:   string;
  password: string;
}

export interface LoadTestUsersFile {
  users: LoadTestUser[];
}

// Shape of the local /health endpoint we sanity-check before kicking off
// the warm-up loop.
export interface HarnessHealth {
  ok:               boolean;
  fixturesLoaded:   number;
  realmLoaded:      string | null;
  pendingOidcFlows: number;
  tcBase:           string;
  tcRealm:          string;
  oidcClientId:     string;
  callbackUrl:      string;
}

// Shape of the harness POST /warmup/oidc/begin response.
export interface OidcBeginResponse {
  ok:      boolean;
  state:   string;
  authUrl: string;
}

// Shape of the harness GET /warmup/oidc/await/:state response.
//
// `sessKeySerialized` and `tideDoken` are the Option B carve-out fields — see
// the comment block at the top of oidc.ts (ALLOWLIST_CARVE_OUT_REALMS).
// `sessKeySerialized` is the serialized PRIVATE component of the SWE session
// keypair; `tideDoken` is the SWE-issued Tide doken JWT (alg=EdDSA, typ=doken;
// distinct from the OIDC access_token returned on `doken`). Both are captured
// in-page during login and forwarded through this response so the warm-up can
// bake them into fixtures.json. SENSITIVE; never log either field server-side.
export interface OidcAwaitResponse {
  ok:                boolean;
  userId?:           string;
  doken?:            string;            // OIDC access_token (alg=RS256, typ=JWT) — TideCloak /token endpoint
  refreshToken?:     string | null;
  expiresInSeconds?: number | null;
  sessKeySerialized?: string | null;    // base64 private TideKey component (Option B carve-out)
  tideDoken?:        string | null;     // Tide doken JWT (alg=EdDSA, typ=doken) — what AuthorizedSigningFlow consumes
  code?:             string;
  message?:          string;
}
