//
// Sign-iteration driver for the load harness.
//
// Each call to runSign() should perform exactly one
// AuthorizedSigningFlow.signv2() against the live ORK network, using
// the credentials baked into the UserFixture by the Playwright warm-up
// pass, plus the shared RealmFixture (vvkid / orks / voucherURL /
// homeOrkUrl) that is captured once per warm-up and is identical for
// every user in the realm.
//
// The body is a clearly-marked TODO: the actual wiring needs the real
// tide-js (de)serialization signatures for Doken / TideKey / etc., which
// will be confirmed by the Main Agent against the live API in v1.1.
// The interfaces (UserFixture / RealmFixture / RunResult) are the
// contract Locust and the warm-up agree on, so they stay stable even
// while the body changes.
//

// The following imports pin the v1.1 wiring surface — if any of these
// namespace exports drift in @tideorg/js, `tsc` will fail here. The
// `@ts-expect-error` markers that used to live here have been removed
// because the parent's emitted .d.ts now resolves Flow/Models/Cryptide
// cleanly (the prepare-script clean+tsc fix in tide-js/package.json
// unblocked the workspace install). The unused-import suppression is in
// tsconfig (`noUnusedLocals` not set), so this compiles clean today.
import { Flow, Models, Cryptide } from "@tideorg/js";

//
// Corrected schema (see SERIALIZATION-NOTES.md §"Updated fixture shape
// (corrected)"). The per-user fixture is now tiny — Doken plus identity
// — because (a) the SWE-error-reporting allowlist forbids capturing
// private bytes, (b) tide-js generates a fresh ephemeral TideKey per
// Sign via TideKey.NewKey(), and (c) all the realm-level public state
// (vvkid, vvkPublic, orks, voucherURL, homeOrkUrl) is identical across
// every user in the realm and now lives on RealmFixture.
//
export interface UserFixture {
  userId: string; // Keycloak username (e.g. "metrics-load-001")
  vuid:   string; // Tide-derived hash (from first-broker-login auto-username)
  doken:  string; // OIDC access_token from TideCloak (the BIG capture)

  // Optional v1 fields — captured by the warm-up alongside `doken` but
  // not yet consumed by runSign(). Wired in v1.1 if measured first-run
  // latency forces us off the "rewarm-before-each-run" operational path
  // and onto refresh-on-demand. See server.ts /warmup/oidc/await/:state
  // and the security note in exchangeCodeForToken().
  refreshToken?:    string;
  dokenExpiresAt?:  string; // ISO timestamp; warm-up = capturedAt + expires_in
}

export interface OrkInfo {
  orkID:            string;
  orkURL:           string;
  orkPublic:        string; // base64 or hex Point (confirm on first warm-up)
  orkPaymentPublic: string;
}

export interface RealmFixture {
  realm:       string;     // "tide-metrics-load"
  vvkid:       string;     // gVVK from SWE URL (hex)
  vvkPublic:   string;     // Point Serialize() format
  voucherURL:  string;     // pattern; per-session sessionId+tabId baked at iteration time
  homeOrkUrl:  string;     // "https://sork1.tideprotocol.com"
  orks:        OrkInfo[];  // fetched once per warm-up from <homeOrkUrl>/Network/Authentication/Node/Some
}

export interface RunResult {
  ok: boolean;
  durationMs: number;
  requestCount?: number;
  code?: string;
  message?: string;
}

export async function runSign(
  user: UserFixture,
  realm: RealmFixture,
): Promise<RunResult> {
  const start = performance.now();
  try {
    // TODO(v1.1): implement against real tide-js API:
    //   1. Reconstruct tide-js types from the realm + user fixture:
    //        - Doken.fromString(user.doken)   (or whatever the deserializer is)
    //        - Point.fromBase64(realm.vvkPublic)
    //        - OrkInfo[] from realm.orks
    //   2. Generate the ephemeral session key fresh per iteration:
    //        - sessKey = TideKey.NewKey(...)
    //      (NOT carried in the fixture — see SERIALIZATION-NOTES.md §
    //      "Also: sessKey is ephemeral, not captured".)
    //   3. Build an AuthorizedSigningFlow(homeOrk, orks, doken, sessKey, ...).
    //   4. Build a BaseTideRequest for a fixed test JWT-shape claim payload
    //      (load test only — content doesn't matter, shape does).
    //   5. await flow.signv2(request, /*waitForAll*/ false);
    //   6. Return { ok: true, durationMs, requestCount: realm.orks.length }.
    //
    // TODO(v1.1 follow-up): refresh-on-demand. If load tests start more
    // than ~5min after warm-up, user.doken may have expired. When
    // user.refreshToken is present and user.dokenExpiresAt is in the
    // past (or close to it), POST to the TideCloak token endpoint with
    // grant_type=refresh_token before calling signv2(). See
    // server.ts /warmup/oidc/await/:state for the field source.
    //
    // The skeleton intentionally throws so anyone running the harness
    // server before v1.1 wiring lands sees a clear error rather than a
    // silent success.
    void user;
    void realm;
    void Flow;
    void Models;
    void Cryptide;
    throw new Error(
      "TODO(v1.1): implement runSign once tide-js Doken.fromString + TideKey.NewKey signatures are confirmed by Main Agent",
    );
  } catch (e: any) {
    return {
      ok: false,
      durationMs: performance.now() - start,
      code: e?.code ?? "TIDE-HARNESS-UNKNOWN",
      message: String(e?.message ?? e),
    };
  }
}
