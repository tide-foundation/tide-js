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
