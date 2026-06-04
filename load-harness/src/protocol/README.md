## load-harness/src/protocol — browserless cmkOnly login client (v2)

Pure-Node implementation of the SWE cmkOnly login flow, replacing the
browser-per-VU driver from v1 (capped ~30-50 VUs/machine). Targets
1000-10000 concurrent VUs by running the protocol path directly:

  Fetch 1 (TideCloak)  GET .../auth?... → 303 → /broker/tide/login → 303 → SWE URL
                       Captures: sid, gVVK, authorizerPack, vRedirectUri, etc.
                                 + KC_AUTH_SESSION_HASH cookie (Max-Age=60s).
  Crypto (ORK fan-out) voucher POST + Convert + Authenticate → vendorEncryptedData.
  Fetch 2 (TideCloak)  GET <vRedirectUri>?state=...&vendorEncryptedData=...
                       → 302 to <redirect_uri>?code=...&state=...

R3 scope (this round): scaffolding + Fetch 1 only. R4 ports the crypto.

See METRICS-INITIATIVE.md and the loadtest-signv2-sessionkey-blocker memory
for why the browserless path is the chosen one.
