# Wire-format observations for `runSign.ts`

> Captured 2026-06-02 from a live SWE login on `tide-metrics-load` at `https://staging.dauth.me` against `sork1.tideprotocol.com`. Production minified tide-js — class names are single-letter (`E`, `I`, `u`) so the runtime introspection below is the source of truth, not the source-tree names.

## 1. Enclave singleton

`window.__tideEnclave` is the live SWE enclave instance, present on `sork1.tideprotocol.com` during the `cmkOnly` flow. Its 16 instance fields:

```
isHidden                  — function (UI guard)
checkForQRCodeSignIn      — function (UI bound)
SessionKey                — TideKey instance (constructor `u`)
_vendorPublic             — Point instance (constructor `E`); vvkPublic
_sessionId                — string (e.g. "utpldoi2GOTSu-lnyfbFpa7g")
_vendorRotatingPublic     — Point instance (constructor `E`); gVRK
_clientDPoPKey            — TideKey or related signing key (DO NOT capture)
_voucherURL               — string (TideCloak mint endpoint, query-string-laden)
_enclaveStorageService    — service wrapper around localStorage
activeOrks                — OrkInfo[]; 0 at page-load, populates during flow
_signedSettings           — { RegOn, BackupOn, LogoURL, ImageURL }
vReturnURL                — string (TideCloak callback)
_regOn                    — boolean (mirror of signedSettings.RegOn)
_overrideRegOn            — boolean
reserveUIDData            — string (per-session reservation receipt)
selectedOrksFunc          — function (cohort selector)
```

After successful login the SWE redirects via something OTHER than `window.location.assign`/`.replace` (these were patched and intercepts didn't fire) — likely a form POST or direct `window.location.href = ...` assignment (browser-protected, can't be patched). The hook-and-capture approach needs a different angle: monkey-patch `EnclaveBase.prototype._finalize` OR set a `MutationObserver` for the post-success UI state.

## 2. `TideKey` (`SessionKey`)

Confirmed methods on the prototype:

```
constructor
get_private_component()       — returns the private TideComponent (DO NOT serialize)
get_public_component()        — returns the public TideComponent
sign(message)
verify(signature, message)
asymmetricDecrypt(...)
asymmetricEncrypt(...)
prepVouchersReq(...)
```

For the fixture (and for `runSign.ts` deserialization), we only need:
- `.get_public_component().Serialize()` → likely a base64 string (need to confirm by calling on a captured key during warm-up). This goes into `fixture.sessKey`.

## 3. `_vendorPublic` / `_vendorRotatingPublic` (Point, class `E`)

`toString()` returns `"[object Object]"` — Point lacks a default string serializer. tide-js source has `Cryptide/Components/...` Point classes that support `Serialize()` → hex/base64. Need to call `.Serialize()` and/or `.toBase64()`/`.toHex()` on a live instance during warm-up to confirm.

## 4. The SWE URL — parameters

Login redirect URL on `sork1.tideprotocol.com` carries (per captured run):

| Param | Type | Per-realm / per-session | Source |
|---|---|---|---|
| `sid` | string | per-session | TideCloak auth-session id |
| `gVVK` | hex string | per-realm (stable for the realm's tide-vendor-key) | Realm `tide-vendor-key` component |
| `authorizerPack` | hex blob | per-realm | Cohort + auth-server descriptor |
| `gVRKSignature` | base64 | per-realm | Signed by vendor's gVRK |
| `vRedirectUri` | URL | per-realm | TideCloak's `…/broker/tide/endpoint` |
| `rURISignature` | base64 | per-realm | Signs `vRedirectUri` |
| `signedSettings` | JSON | per-realm | `{ RegOn, BackupOn, LogoURL, ImageURL }` |
| `settingsSignature` | base64 | per-realm | Signs `signedSettings` |
| `voucherURL` | URL | per-session-tab | TideCloak's `…/tidevouchers/fromAuthSession?sessionId=…&tabId=…&clientId=…` |
| `type` | enum | constant | `cmkOnly` for the password flow |
| `state` | string | per-OIDC-roundtrip | Keycloak OIDC state + tab id |

For the warm-up: fetch the per-realm values ONCE from the realm's IdP config, fan them into per-user fixtures. Per-session sid/state/voucherURL come from each TideCloak OIDC authorize redirect.

## 5. `activeOrks` (OrkInfo[])

Populated mid-flow by `NodeClient.GetSomeORKs()` (a fetch to `/Network/Authentication/Node/Some` on the home ORK). Length=10 at staging time of capture, matching `TOTAL_ORKS=10`.

Each OrkInfo (from tide-js source — `Models/Infos/OrkInfo.ts`):
```
orkID            — string (UUID-ish)
orkURL           — string (https://sork<n>.tideprotocol.com)
orkPublic        — Point
orkPaymentPublic — Point
```

Warm-up should fetch this once per realm (the cohort is realm-level, not user-level) and bake it into every user fixture.

## 6. localStorage on `sork1.tideprotocol.com`

After a successful login, persisted keys (truncated, prefix-only):

```
currentLanguage    = "en"
timeSkew           = "3"
Xcfvwe4uBwt+ju/Ua3UZu4i9DnNUDQSPPw9Xp25xJF8= = EAAA...   ← EnclaveEntry (base64 of EnclaveEntry.toString())
                                                          NB: includes Tide_Entry private bytes —
                                                          DO NOT serialize into the fixture per
                                                          SWE-error-reporting allowlist.
```

The EnclaveEntry key (a hash of (vendorPub, vuid)) maps to the persisted entry. Useful for the SWE to skip re-keygen on repeat sign-ins, but the **private bytes inside it must never leave the browser**.

## 7. The Doken (the missing piece)

Not captured. The Doken is:
- Produced by the SWE on successful CMK auth (mid-flow)
- Returned to TideCloak as part of `vendorEncryptedData` (encrypted under realm's `activeVrk`)
- The OIDC access_token TideCloak then issues to the client

Three viable capture paths for the warm-up:
- **(a) Monkey-patch `EnclaveBase.prototype._finalize`** or whatever method is called just before the SWE returns control to TideCloak. Override to dump `this.Doken.toString()` (or equivalent) into a known global before forwarding.
- **(b) Capture the OIDC access_token** from the account-console's keycloak-js instance after the broker login completes (`window.keycloak.token` if keycloak-js is loaded as a global; in the JIT shadow-DOM tester it isn't, so this needs a custom test page that loads keycloak-js with `window.keycloak = kc`).
- **(c) Direct Grant?** **Will NOT work** — Tide-IdP realms always route token issuance through Midgard.SignModel, but the Doken specifically is the SWE's CMK-auth artifact, not just any signed token. Direct Grant would skip the CMK keygen/auth entirely and produce a regular token that the harness's `AuthorizedSigningFlow` would reject.

Strong recommendation: **path (a)** — drive the warm-up Playwright flow against a sork URL with an `init_script` (via Playwright's `page.addInitScript`) that monkey-patches the relevant prototype chain. The same script can also stash the Doken into `sessionStorage` so Playwright can read it after the redirect.

## 8. Runtime artifacts the warm-up must round-trip into the fixture

```typescript
interface UserFixture {
  userId:      string;                 // Keycloak username
  vuid:        string;                 // SHA-256-ish Tide-derived hash; from first-broker-login auto-username
  doken:       string;                 // From SWE mid-flow (path (a) above)
  sessKey:     string;                 // TideKey.get_public_component().Serialize() → likely base64
  vvkid:       string;                 // From SWE URL gVVK (hex)
  vvkPublic:   string;                 // Same as vvkid? Or a Point.Serialize() of it
  orks: Array<{
    orkID:           string;
    orkURL:          string;
    orkPublic:       string;           // base64 or hex Point
    orkPaymentPublic: string;          // base64 or hex Point
  }>;
  voucherURL:  string;
  homeOrkUrl:  string;
}
```

The serialization format (base64 vs hex) needs one more confirmation during the warm-up. Pick a single user, call `.Serialize()` on a captured Point and TideKey public component, log to console, observe.

---

## Probe result (2026-06-02) — design correction

Live runtime introspection of `window.__tideEnclave.constructor.prototype` (class `I`, extending `G`) on a fresh `?type=cmkOnly` SWE load. Method signatures confirmed by `Function.prototype.toString()`:

**`I.prototype._finalize(e)`** (49 chars):
```js
async _finalize(e) { this._redirectBackToVendor(e); }
```

**`I.prototype._redirectBackToVendor(e)`** (262 chars):
```js
async _redirectBackToVendor(e) {
  const t = new URL(this.vReturnURL),
        s = new URLSearchParams(window.location.search);
  // ... appends e (vendorEncryptedData) + state to the query string
  // ... then location.href = t.toString();
}
```

`G.prototype._finalize()` is the abstract stub (`throw Error("Not implemented")`).

### The Doken-capture design correction

`_finalize(e)` receives `vendorEncryptedData`, NOT a Doken. The Doken is the **OIDC access_token** TideCloak issues AFTER `Endpoint.authResponse` consumes `vendorEncryptedData` and mints a Keycloak session. So monkey-patching `_finalize` does NOT give us a Doken directly.

The **correct** warm-up design — standard OIDC, no prototype hacking:

1. **One-time admin setup**: register a public OIDC client `tide-loadtest-harness` in TideCloak (`redirect_uri=http://localhost:3000/callback`, PKCE enabled).
2. **Per user**:
   - `page.goto('<TideCloak>/realms/tide-metrics-load/protocol/openid-connect/auth?client_id=tide-loadtest-harness&kc_idp_hint=tide&redirect_uri=http://localhost:3000/callback&response_type=code&...')`
   - Playwright drives the SWE sign-in form (already verified works against `metrics-load-001` / `Load-QA-2026!`).
   - On SWE success, browser redirects to `http://localhost:3000/callback?code=…`.
   - Harness's Express server has a `/callback` route that captures the `code`.
   - Harness exchanges the code at `<TideCloak>/realms/tide-metrics-load/protocol/openid-connect/token` (`grant_type=authorization_code`, `code_verifier=...`).
   - The returned `access_token` IS the Doken.

No monkey-patching. No private state extraction. Pure OIDC.

### Also: `sessKey` is ephemeral, not captured

From the tide-js PM Phase 1 audit:
- `AuthorizedSigningFlow` takes `sessKey: TideKey` as an **ephemeral session key**, generated fresh per Sign via `TideKey.NewKey(...)`.
- It is NOT the user's persistent CMK-derived key.
- The harness's `runSign.ts` generates a fresh `TideKey.NewKey()` each iteration; no fixture serialization needed for it.

### Updated fixture shape (corrected)

```typescript
interface UserFixture {
  userId:      string;     // Keycloak username (e.g. "metrics-load-001")
  vuid:        string;     // Tide-derived hash (from first-broker-login auto-username)
  doken:       string;     // OIDC access_token from TideCloak (the BIG capture)
  // No sessKey — generated fresh per Sign via TideKey.NewKey()
}

interface RealmFixture {
  realm:       string;     // "tide-metrics-load"
  vvkid:       string;     // gVVK from SWE URL (hex), or Realm Settings → Keys → tide-vendor-key
  vvkPublic:   string;     // Point (Serialize() format TBD on first warm-up — base64 likely)
  voucherURL:  string;     // Pattern; per-session sessionId+tabId baked at iteration time
  homeOrkUrl:  string;     // "https://sork1.tideprotocol.com"
  orks:        OrkInfo[];  // Fetched ONCE per warm-up from <homeOrkUrl>/Network/Authentication/Node/Some
}
```

The warm-up writes `{ realm: RealmFixture, users: UserFixture[] }` to `fixtures.json`.

---

## Round-15 correction (2026-06-02)

Live source-tree inspection of the TideCloak token-issuance path overturns substantial parts of the R7 and R12 capture designs. The Tide doken does NOT have to be lifted out of the browser — TideCloak attaches it directly to the OIDC `/token` JSON response as a top-level sibling field of `access_token`, named `doken` (lowercase).

The path:
- `TokenManager.responseBuilder().build()` (Keycloak's `TokenManager.java:1406-1408`) calls `setOtherClaims("doken", encodedTokens[2])` on the `AccessTokenResponse` when the Tide IdP has placed an encoded Tide doken into the token-exchange context. `encodedTokens[2]` is the 3-part JWT serialization of the doken (header `alg=EdDSA, typ=doken`).
- `AccessTokenResponse.otherClaims` is a `Map<String, Object>` annotated with `@JsonAnyGetter`, so Jackson flattens it onto the top level of the response JSON during serialization (see `DefaultTokenManager.java:489-555` for the surrounding builder logic). The wire shape is therefore:
  ```json
  {
    "access_token": "eyJ…",
    "refresh_token": "eyJ…",
    "expires_in": 300,
    "doken": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRva2VuIn0…"
  }
  ```
- The harness's `exchangeCodeForToken()` (R15) parses that `doken` field directly. No in-page extraction required, no race against the SWE → TideCloak → `/callback` redirect chain.

The R10-R12 "capture Doken from `__tideEnclave`" path is wrong: the cmkOnly login enclave does not expose a `doken` field. The previous in-page pump's success predicate (`enc.SessionKey && enc.doken`) was waiting on a property that is never set on this enclave instance. The R13 pump was lucky to fire at all — what it was actually waiting for were timing artefacts.

The carve-out POST endpoint (`POST /warmup/oidc/sesskey/:state`) is consequently narrowed in R15 to `{ sessKeySerialized }` only. The body's `tideDoken` field is dropped from the contract; the server deliberately ignores it if a stale warm-up still sends it.

The SessionKey carve-out remains scoped to the `tide-metrics-load` realm via `ALLOWLIST_CARVE_OUT_REALMS`. The reason is **not** the Doken — it is that `AuthorizedSigningFlow.signv2()` requires the SessionKey **private** half to sign the per-ORK request bodies, and that private material is the only thing in the SWE enclave that can't be regenerated server-side. The realm gate keeps the in-page private-key extractor from becoming a general-purpose exfiltration tool; widening it must require orchestrator + user sign-off.
