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
import { Flow, Models, Cryptide, Clients } from "@tideorg/js";

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
  // OIDC access_token from TideCloak's /token endpoint — alg=RS256,
  // typ=JWT, payload has standard OIDC claims + tideuserkey + vuid.
  // NOT consumed by runSign(); kept for /userinfo validation and
  // diagnostic uses (R12 — see SWE-issued tideDoken below).
  doken:  string;

  // Optional v1 fields — captured by the warm-up alongside `doken` but
  // not yet consumed by runSign(). Wired in v1.1 if measured first-run
  // latency forces us off the "rewarm-before-each-run" operational path
  // and onto refresh-on-demand. See server.ts /warmup/oidc/await/:state
  // and the security note in exchangeCodeForToken().
  refreshToken?:    string;
  dokenExpiresAt?:  string; // ISO timestamp; warm-up = capturedAt + expires_in

  // Option B carve-out (2026-06-02): private-equivalent SWE session keypair, captured ONLY for tide-metrics-load — see warmup/oidc.ts ALLOWLIST_CARVE_OUT_REALMS and ~/.claude/.../memory/loadtest-signv2-sessionkey-blocker.md.
  sessKeySerialized?: string;

  // R12 (2026-06-02): Tide-issued doken (alg=EdDSA, typ=doken) lifted from
  // `window.__tideEnclave.doken.serialize()` during the SWE login window
  // — the actual credential AuthorizedSigningFlow's constructor consumes
  // (it carries `t.ssk` bound to sessKeySerialized's public component and
  // `t.uho` = home ORK URL). Distinct from the OIDC access_token above.
  // Captured under the same realm gate as sessKeySerialized.
  tideDoken?: string;
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

// Cache of KeyInfo fetched via Clients.NetworkClient.GetKeyInfo(vvkid).
// The result is realm-stable (same vvkid → same KeyInfo across every user
// in the realm), and the fetch is one-extra-RTT on the home ORK. We cache
// it for the lifetime of the harness process. Keyed by vvkid to keep the
// cache structurally sound if a future runSign() call ever switches
// realms mid-process. The map value is a Promise so concurrent first-time
// callers share one fetch.
const _keyInfoCache = new Map<string, Promise<any>>();
function getKeyInfo(realm: RealmFixture): Promise<any> {
  const existing = _keyInfoCache.get(realm.vvkid);
  if (existing) return existing;
  const client = new (Clients as any).NetworkClient(realm.homeOrkUrl);
  const p = client.GetKeyInfo(realm.vvkid);
  _keyInfoCache.set(realm.vvkid, p);
  // If the fetch fails, drop the cache entry so a retry can try again.
  p.catch(() => _keyInfoCache.delete(realm.vvkid));
  return p;
}

export async function runSign(
  user: UserFixture,
  realm: RealmFixture,
): Promise<RunResult> {
  const start = performance.now();
  try {
    // 1. Refuse outside the Option B carve-out. The warm-up's realm gate
    //    (warmup/oidc.ts ALLOWLIST_CARVE_OUT_REALMS) is the primary
    //    refusal; this is belt-and-braces in case fixtures from a
    //    different realm are ever loaded by mistake. R12: tideDoken is
    //    captured in the same code path as sessKeySerialized, so we now
    //    require BOTH — a fixture with one but not the other is a
    //    pre-R12 capture and won't validate.
    if (!user.sessKeySerialized) {
      throw new Error(
        "runSign requires user.sessKeySerialized — fixture was not produced under the Option B carve-out (see warmup/oidc.ts ALLOWLIST_CARVE_OUT_REALMS)",
      );
    }
    if (!user.tideDoken) {
      // R11 finding: the OIDC access_token captured on user.doken is
      // alg=RS256, typ=JWT and lacks the `t.ssk` / `t.uho` payload that
      // AuthorizedSigningFlow's constructor expects — only the SWE-issued
      // tideDoken (alg=EdDSA, typ=doken) works. The field-name split
      // (doken vs tideDoken) makes intent obvious so we no longer need
      // a runtime alg/typ guard; this presence check covers the
      // pre-R12-fixture case directly.
      throw new Error(
        "runSign requires user.tideDoken — fixture is pre-R12 (captured before warmup/oidc.ts started lifting __tideEnclave.doken.serialize() alongside the sessKey). Re-run the warm-up to capture it. The OIDC access_token on user.doken is NOT a substitute (see R11 finding).",
      );
    }

    // 2. Reconstruct tide-js types from the fixture.
    //
    //    sessKey: TideKey.FromSerializedComponent → BaseComponent.Deserialize
    //    Component is the canonical inverse of `.Serialize().ToString()`.
    //    Verified end-to-end with the fixtures.json sample on 2026-06-02
    //    (see /home/alphega/project/tide-js/load-harness/src/sesskey_test.ts):
    //    decoded 35 bytes → keyType=Private(1), scheme=Ed25519(0), 32-byte
    //    payload → reconstructed Ed25519PrivateComponent → derived public
    //    component matches a valid Ed25519 point. This factory IS generic
    //    over Public/Private/Seed via the embedded keyType nibble in byte 0.
    //
    //    doken: new Doken(jwt) parses the 3-part JWT and DeserializeComponents
    //    the `t.ssk` / `tideuserkey` payload fields. CRITICAL: the doken
    //    string must be the SWE-issued Tide doken (alg=EdDSA, typ=doken,
    //    payload containing `t.ssk` + `t.uho`) — `user.tideDoken`, NOT
    //    `user.doken`. The latter is the OIDC access_token returned by
    //    TideCloak's /token endpoint (alg=RS256, typ=JWT) which lacks
    //    t.ssk/t.uho and would fail the constructor's session-key lookup.
    //    See R11's finding and the UserFixture type comments above.
    const sessKey = (Cryptide as any).TideKey.FromSerializedComponent(user.sessKeySerialized);
    const doken = new (Models as any).Doken(user.tideDoken);

    // 3. Build KeyInfo. The SWE fetches this server-side from the home
    //    ORK at /Network/Authentication/Users/UserInfo/{vvkid} via
    //    Clients.NetworkClient.GetKeyInfo. The result is realm-stable
    //    (same KeyInfo for every user in the realm — the vendorInfo
    //    field on the enclave) so we cache it across runSign calls.
    const keyInfo = await getKeyInfo(realm);

    // 4. Build the AuthorizedSigningFlow. The constructor field names
    //    are pinned by AuthorizedSigningFlow.ts:27 and match the SWE's
    //    own call site in ork/...Enclave/Types/Request/RequestEnclave.js.
    const SigningFlows = (Flow as any).SigningFlows;
    const flow = new SigningFlows.AuthorizedSigningFlow({
      vendorId:    realm.vvkid,
      token:       doken,
      sessionKey:  sessKey,
      voucherURL:  realm.voucherURL,   // Path-α patched form (with <PER_SESSION>/<PER_TAB>/<PER_REALM> placeholders or live values)
      homeOrkUrl:  realm.homeOrkUrl,
      keyInfo,
    });

    // 5. Fixed test request payload. Per the brief, the content is
    //    irrelevant — we're measuring the Sign round-trip, not validating
    //    the signature against a real consumer. We use a tiny JWT-shape
    //    claim so the on-wire request shape is plausible for any future
    //    capture.
    const now = Math.floor(Date.now() / 1000);
    const draft = new TextEncoder().encode(JSON.stringify({
      sub:   user.vuid,
      aud:   "load-harness-test",
      scope: "openid",
      iat:   now,
      exp:   now + 60,
    }));
    const req = new (Models as any).BaseTideRequest(
      "LoadHarnessTest",
      "1",
      "Doken:1",
      draft,
    );
    const serializedReq = req.encode();

    // 6. Drive Sign. waitForAll=false → return as soon as Threshold ORKs
    //    have responded, which is the same operational mode the SWE uses
    //    for interactive Sign calls. This is what makes the load test
    //    representative of real-user latency.
    await flow.signv2(serializedReq, /*waitForAll*/ false);

    return {
      ok: true,
      durationMs: performance.now() - start,
      requestCount: realm.orks.length,
    };
  } catch (e: any) {
    return {
      ok: false,
      durationMs: performance.now() - start,
      code: e?.code ?? "TIDE-HARNESS-UNKNOWN",
      message: String(e?.message ?? e),
    };
  }
}
