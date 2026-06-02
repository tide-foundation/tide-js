//
// Per-user OIDC capture (Section A of the warm-up).
//
// One call to captureUserFixture():
//   1. POST <HARNESS_URL>/warmup/oidc/begin { userId } → { state, authUrl }
//   2. Open a fresh Playwright BrowserContext (clean cookies + storage).
//   3. page.goto(authUrl). Keycloak redirects to sork1.tideprotocol.com
//      because of kc_idp_hint=tide.
//   4. Drive the SWE login form (single screen: username + password +
//      Sign In div).
//   5. Wait for the page to redirect to <HARNESS_URL>/callback?code=...
//   6. GET <HARNESS_URL>/warmup/oidc/await/:state → { doken, refreshToken,
//      expiresInSeconds }.
//   7. Decode the JWT, pull vuid from the appropriate claim.
//   8. Return a UserFixture.
//
// Selector strategy (Round 7):
//   The SWE login form is built with Web Components. Every input field
//   is a <custom-input> host element with the real <input> nested
//   inside element.shadowRoot. Top-level CSS selectors like
//   `input[name="username"]` do NOT match (no such element exists in
//   the light DOM). The hosts have stable IDs which we target directly:
//     custom-input#sign_in-input_name      → username
//     custom-input#sign_in-input_password  → password
//   The Sign In trigger is a clickable <div class="sign_in-button">.
//   Round 6 tried a structural :has() selector keyed on the <p.text>
//   "Sign In" + sibling arrow_right image. That selector matched
//   FOUR ancestor divs (button, inputs, default, page.cut), and
//   .filter({hasText:'Sign In'}).first() returned the OUTERMOST
//   (page.cut, the entire form container). Playwright clicked the
//   center of that bbox, which landed in the input area and focused an
//   input rather than submitting. The Orchestrator probe (Round 7)
//   confirmed `div.sign_in-button` is a stable, unique class — the
//   button's own bbox center is on the button itself, so a default
//   .click() submits the form and the chain navigates all the way to
//   <callbackOrigin>/callback?code=…&state=…
//
// SECURITY:
//   * The user's password egress is exactly one place: fillCustomInput()
//     of the password host's shadow <input>. It is NOT logged anywhere
//     — not on success, not on failure, not in catch blocks (we strip
//     it from any thrown Error.message we surface from oidc.ts).
//   * The doken and refreshToken received from the harness pass
//     through this module verbatim into the returned UserFixture. We
//     do NOT log them (the harness server has the same rule; see
//     server.ts /warmup/oidc/await/:state).
//   * Debug dump (WARMUP_DEBUG_DUMP=true): we dump page HTML + screenshot
//     ONLY on selector-resolution failures (i.e. before any field has
//     been filled). Post-fill failures bypass the dump to guarantee no
//     password leak via dumped HTML or visible-form screenshot.
//

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import type { BrowserContext } from "playwright";
import type { UserFixture } from "../runSign.js";
import type {
  LoadTestUser,
  OidcAwaitResponse,
  OidcBeginResponse,
} from "./types.js";

declare const fetch: typeof globalThis.fetch;

// ---------------------------------------------------------------------------
// Option B carve-out (R10): session-key (private-equivalent) capture.
//
// The harness's runSign() drives AuthorizedSigningFlow.signv2() server-side,
// outside any browser. The flow's constructor checks that the supplied
// sessionKey's public component equals the Doken payload's sessionKey, so we
// cannot mint a fresh TideKey.NewKey() and expect the captured Doken to
// validate. The ONLY way to make Sign work is to lift the SAME session-key
// material that the SWE wrote during CMK auth out of the browser.
//
// This material is private-equivalent (it's the session keypair the Doken
// is bound to — anyone with it can mint Sign requests for the user until
// the Doken expires). The carve-out is therefore tightly scoped:
//
//  1. ONLY for the load-testing realm. The list below is checked at capture
//     time; the warm-up refuses to even attempt extraction in any other realm.
//  2. ONLY the session keypair — no Tide_Device_Key, no Tide_Entry, no
//     _clientDPoPKey, no decrypted models, no inputs/cookies/headers.
//  3. Egress path is /warmup/oidc/await/:state JSON → fixtures.json on disk.
//     NEVER through the SWE error-reporting buildReportPayload path; that
//     allowlist + its tests in ork/ must remain unchanged.
//  4. fixtures.json is gitignored and handled as a realm-export-grade secret.
//
// Future maintainers: do NOT widen this list without orchestrator + user
// sign-off. The realm gate is the only thing keeping this from becoming a
// general-purpose key exfiltration tool.
// ---------------------------------------------------------------------------
export const ALLOWLIST_CARVE_OUT_REALMS = ["tide-metrics-load"] as const;
type CarveOutRealm = typeof ALLOWLIST_CARVE_OUT_REALMS[number];

function isCarveOutRealm(realm: string): realm is CarveOutRealm {
  return (ALLOWLIST_CARVE_OUT_REALMS as readonly string[]).includes(realm);
}

// Selector blocks for the live SWE form (Round 6).
//
// The form is a single screen. Both username and password are visible
// at once. The Sign In trigger is a clickable <div>, not a <button>.
//
// Each "host" selector resolves the <custom-input> light-DOM host;
// fillCustomInput() then reaches into element.shadowRoot to drive the
// real <input>. The Sign In trigger uses the stable `sign_in-button`
// CSS class on the actual button wrapper — confirmed by the Round 7
// Orchestrator probe to drive the form all the way through to the
// /callback redirect.
export const SWE_SELECTORS = {
  usernameHost: "custom-input#sign_in-input_name",
  passwordHost: "custom-input#sign_in-input_password",
  // The clickable submit element on the sign-in screen. The form
  // markup nests this inside three more divs that all happen to match
  // `:has(p.text):has(img[alt="arrow_right"])`, so any structural
  // composition based on the <p> + <img> falls back to the outermost
  // ancestor under Playwright's "first match in DOM order" rule —
  // which is the entire form container, whose bbox center is in the
  // username input. `div.sign_in-button` is the inner element whose
  // bbox center IS on the visible button.
  signInButton: "div.sign_in-button",
} as const;

interface CaptureOptions {
  harnessUrl:      string;     // e.g. http://localhost:3000
  callbackOrigin:  string;     // e.g. http://localhost:3000 (the redirect_uri origin)
  user:            LoadTestUser;
  context:         BrowserContext;
  // Realm name from /health (e.g. "tide-metrics-load"). REQUIRED so the
  // Option B carve-out (in-page session-key extraction) can hard-refuse
  // any realm not on ALLOWLIST_CARVE_OUT_REALMS. Failure to supply it ==
  // capture disabled for this user — Sign won't work but the rest of the
  // warm-up still produces a Doken fixture.
  realm:           string;
  awaitTimeoutMs?: number;
  navTimeoutMs?:   number;
  // Optional sniffer for Path α — invoked with the first SWE URL the
  // browser navigates to (sork*.tideprotocol.com/?…&gVVK=…&voucherURL=…).
  // We call this exactly once per captureUserFixture() so the warm-up
  // can opportunistically backfill any RealmFixture fields Path β
  // didn't capture. Errors from the sniffer are swallowed — Path α is
  // best-effort.
  onSweUrl?:       (url: string) => void;
}

// Timeout policy (Round 7 — reconciled).
//
// There are TWO distinct waits in captureUserFixture():
//
//   * page.waitForURL(...) for the final /callback redirect, AND the
//     paired long-poll to the harness's /warmup/oidc/await/:state.
//     Both use awaitTimeoutMs. This covers the full server-side chain
//     (Sign In click → SWE CMK work → broker → token exchange →
//     redirect_uri hit), which on a slow staging can run close to 90s.
//     We set 120s deliberately to leave headroom; Round 4 QA observed
//     a timeout fire at exactly 120000ms, confirming this is the
//     binding wait.
//
//   * Per-step Playwright defaults (page.setDefaultTimeout +
//     setDefaultNavigationTimeout) and per-selector waitFor() calls.
//     These cover the initial authorize-URL navigation and the SWE
//     form mount; they use navTimeoutMs. 90s here is fine — neither
//     the authorize redirect nor the Web-Component hydration should
//     take that long, and a shorter inner timeout fails fast if the
//     form never renders.
//
// The R4 QA "90s vs 120s" confusion was because both timeouts existed
// and the brief mentioned only "90s nav timeout" without distinguishing
// them. They are intentionally different; the only effective ceiling
// on the end-to-end sign-in is awaitTimeoutMs (120s).
const DEFAULT_AWAIT_TIMEOUT_MS = 120_000;
const DEFAULT_NAV_TIMEOUT_MS   = 90_000;

// Strip the user's password (and any common header / form-data fragments
// that might carry it) out of a string before logging. Defence-in-depth
// for Playwright errors that occasionally echo back surrounding HTML.
function redact(s: string, password: string): string {
  if (!password) return s;
  // Replace verbatim and percent-encoded forms. Don't try to redact
  // single-character passwords — they would over-match.
  if (password.length < 3) return s;
  const enc = encodeURIComponent(password);
  return s.split(password).join("[REDACTED]").split(enc).join("[REDACTED]");
}

// Wait for a <custom-input> host to mount and for its shadow-root
// <input> to be present. Returns the host Locator on success, null on
// timeout. We treat "host attached + shadow input present" as ready —
// not host.visible(), since custom elements sometimes report visible=
// false while their shadow content is interactable.
async function waitForCustomInputHost(
  page: import("playwright").Page,
  hostSelector: string,
  timeoutMs: number,
): Promise<import("playwright").Locator | null> {
  const host = page.locator(hostSelector).first();
  try {
    await host.waitFor({ state: "attached", timeout: timeoutMs });
  } catch {
    return null;
  }
  // Poll for the shadow <input> to exist. Playwright's waitForFunction
  // pierces shadow roots via direct DOM access in evaluate(); we use it
  // for an authoritative check.
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ready = await host.evaluate((el) => {
      const root = (el as Element & { shadowRoot: ShadowRoot | null }).shadowRoot;
      return !!root && !!root.querySelector("input");
    }).catch(() => false);
    if (ready) return host;
    await page.waitForTimeout(100);
  }
  return null;
}

// Fill a <custom-input> host's inner shadow <input>.
//
// Why setter+dispatch rather than Playwright .fill():
//   The host's controlled-state listeners may only fire on a real
//   `input` event from the inner element. Playwright's .fill() doesn't
//   pierce shadow roots without an explicit selector, and even when it
//   does, framework state ignores the synthetic value-change unless we
//   go through HTMLInputElement.prototype.value setter (the standard
//   React-controlled-input incantation, which applies equally to Lit
//   / Stencil / vanilla custom-elements with input listeners).
//
// We also dispatch a `change` event for completeness — some forms
// trigger validation on blur/change rather than input.
async function fillCustomInput(
  host: import("playwright").Locator,
  value: string,
): Promise<void> {
  await host.evaluate((el, v) => {
    const root = (el as Element & { shadowRoot: ShadowRoot | null }).shadowRoot;
    if (!root) throw new Error("custom-input host has no shadowRoot");
    const input = root.querySelector("input") as HTMLInputElement | null;
    if (!input) throw new Error("custom-input shadow <input> not found");
    input.focus();
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    const setter = desc?.set;
    if (!setter) throw new Error("HTMLInputElement.value setter unavailable");
    setter.call(input, v);
    input.dispatchEvent(new Event("input",  { bubbles: true, composed: true }));
    input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    input.blur();
  }, value);
}

// Resolve the Sign In trigger. Returns a Locator that points at the
// clickable button element (the inner <div class="sign_in-button">).
// Confirmed by the Round 7 Orchestrator probe to: (a) be unique on
// the sign-in screen, and (b) have a bbox whose center is on the
// visible button — so a default Playwright .click() (center-of-bbox)
// hits the correct target and submits the form.
async function resolveSignInTrigger(
  page: import("playwright").Page,
  timeoutMs: number,
): Promise<import("playwright").Locator | null> {
  const candidate = page.locator(SWE_SELECTORS.signInButton).first();
  try {
    await candidate.waitFor({ state: "visible", timeout: timeoutMs });
    return candidate;
  } catch {
    return null;
  }
}

export async function beginFlow(harnessUrl: string, userId: string): Promise<OidcBeginResponse> {
  const res = await fetch(`${harnessUrl}/warmup/oidc/begin`, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ userId }),
  });
  if (!res.ok) {
    throw new Error(`/warmup/oidc/begin returned ${res.status} ${res.statusText}`);
  }
  const json = (await res.json()) as OidcBeginResponse;
  if (!json?.ok || !json.state || !json.authUrl) {
    throw new Error(`/warmup/oidc/begin returned malformed body`);
  }
  return json;
}

// POST the captured session-key blob to the harness, which attaches it to
// the matching pending flow so the await response can deliver it. We route
// via the harness (rather than baking into the fixture in this module
// directly) so the egress audit point stays in server.ts — one JSON shape,
// one place to grep when reviewing handling.
//
// R15: the Tide doken is no longer carried on this payload. R14 confirmed
// TideCloak attaches the SWE-issued Tide doken as a top-level `doken`
// sibling field on the /token response (`AccessTokenResponse.otherClaims`
// + @JsonAnyGetter; TokenManager.java:1406-1408), so the harness captures
// it from the token-exchange path and the in-page pump's job is now
// narrowed to just the SessionKey.
async function postCarveOutCapture(
  harnessUrl: string,
  state: string,
  payload: { sessKeySerialized: string },
): Promise<void> {
  const res = await fetch(
    `${harnessUrl}/warmup/oidc/sesskey/${encodeURIComponent(state)}`,
    {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    },
  );
  if (!res.ok) {
    // Body may include code/message but NEVER includes the sessKey we sent.
    const text = await res.text().catch(() => "");
    throw new Error(
      `/warmup/oidc/sesskey/${state.slice(0, 8)}… returned ${res.status}: ${text.slice(0, 200)}`,
    );
  }
}

// In-page extraction of the SWE session key (private-equivalent).
//
// R13: the previous implementation used `page.waitForFunction()` + a
// trailing `page.evaluate()` to observe `window.__tideEnclave` after Sign
// In had been clicked. QA Round 7 showed this races the SWE→TideCloak→
// `/callback` redirect chain: by the time the Node-side `evaluate` runs,
// the page has navigated to the `localhost:3000` callback origin where
// `__tideEnclave` doesn't exist. Even when the `waitForFunction`
// predicate matched (because at the moment of the check we WERE still on
// the SWE origin), the subsequent `evaluate` raced the same redirect.
//
// R13's fix is to run the polling loop IN the page's own JS context
// (installed via `page.addInitScript()` BEFORE the first navigation, so
// it runs on every document including the SWE origin) and ship the
// captured material to Node via `page.exposeFunction()`. The exposed
// function call is synchronous from the page's perspective — the page
// enqueues a message to Node and returns — so even if the SWE redirects
// nanoseconds later, the capture data has already crossed the boundary.
//
// R15: the Tide doken half of the in-page pump has been retired. R14
// confirmed TideCloak attaches the SWE-issued Tide doken as a top-level
// sibling `doken` field on the /token JSON response
// (`AccessTokenResponse.otherClaims` + @JsonAnyGetter;
// TokenManager.java:1406-1408, DefaultTokenManager.java:489-555), and
// observation of `window.__tideEnclave` in the cmkOnly login flow shows
// no `doken` field is exposed on the enclave — the in-page approach was
// chasing a phantom. The pump now resolves as soon as `enc.SessionKey`
// appears, which fires well before the SWE → TideCloak → /callback
// redirect chain begins, removing the redirect-race window that bit R13.
//
// SessionKey: extracted from the live `window.__tideEnclave.SessionKey`
// TideKey instance. The SWE writes this during CMK auth (RequestEnclave.
// _init around line 145).
//
// What we capture: the private component serialization. That's all
// `TideKey.FromSerializedComponent()` consumes on the runSign side; the
// public component is derived from the private via `(component as any)
// .GetPublic()` in TideKey.get_public_component().
//
// What we DO NOT capture:
//   * Tide_Device_Key, Tide_Entry, _clientDPoPKey, _gPass
//   * decrypted models, voucher blur scalars, password inputs,
//     cookies, Authorization headers
// The init script body below references ONLY `__tideEnclave.SessionKey`.
// Nothing else.
interface CarveOutCapture {
  sessKeySerialized: string;
}

// Sentinel error reason emitted via `__captureCarveOutError` when the
// in-page poll budget expires without ever seeing the enclave fields.
const CARVE_OUT_TIMEOUT_REASON = "enclave never observed before timeout";

// Set up the in-page carve-out pump. Installs:
//   * an `addInitScript` that polls `__tideEnclave` and calls the exposed
//     functions when the SessionKey appears, and
//   * `__captureCarveOut(cap)` / `__captureCarveOutError({reason})`
//     exposed functions that resolve / reject the returned promise.
//
// Returns:
//   * `capturedPromise`: resolves with the capture, or rejects with an
//     Error tagged with a `.reason` string from the in-page side.
//   * `dispose()`: idempotent; clears the per-page state so a late
//     in-page call is a no-op (defence-in-depth against the page
//     trying to call the exposed function after we've finished).
//
// Must be invoked BEFORE the first `page.goto()` so the init script
// runs on every document the page loads — crucially the SWE origin,
// where `__tideEnclave` lives.
export async function installCarveOutPump(
  page: import("playwright").Page,
  realm: string,
): Promise<{
  capturedPromise: Promise<CarveOutCapture>;
  dispose: () => void;
}> {
  // Per-page Node-side closure state. Defence-in-depth: even if the
  // exposed function were called for a realm not on the allowlist (it
  // shouldn't be — the init script gates on realm too), we refuse here.
  let settled = false;
  let resolve!: (cap: CarveOutCapture) => void;
  let reject!: (e: Error & { reason?: string }) => void;
  const capturedPromise = new Promise<CarveOutCapture>((res, rej) => {
    resolve = res;
    reject  = rej;
  });

  const realmAllowed = isCarveOutRealm(realm);

  await page.exposeFunction(
    "__captureCarveOut",
    (cap: { sessKeySerialized?: unknown }) => {
      if (settled) return;
      // Defence-in-depth realm gate on the Node side.
      if (!realmAllowed) return;
      const sessKeySerialized =
        typeof cap?.sessKeySerialized === "string" && cap.sessKeySerialized.length > 0
          ? cap.sessKeySerialized
          : null;
      if (!sessKeySerialized) return;
      settled = true;
      resolve({ sessKeySerialized });
    },
  );

  await page.exposeFunction(
    "__captureCarveOutError",
    (err: { reason?: unknown }) => {
      if (settled) return;
      if (!realmAllowed) return;
      const reason =
        typeof err?.reason === "string" && err.reason.length > 0
          ? err.reason
          : "unknown error";
      settled = true;
      const e = new Error(reason) as Error & { reason: string };
      e.reason = reason;
      reject(e);
    },
  );

  // The init script. Kept compact — runs on every document the page
  // navigates to, but early-returns on realm mismatch and on documents
  // where it's already running. The 50ms poll is comfortably faster
  // than the SWE → TideCloak → /callback redirect chain. R15: success
  // predicate is `enc.SessionKey` only — the SessionKey is populated
  // during CMK auth, well before the redirect chain begins, so the
  // capture lands long before the JS context can be torn down.
  await page.addInitScript(
    ({ realm: r, allowedRealms }: { realm: string; allowedRealms: readonly string[] }) => {
      // Per-document realm gate. Defence-in-depth: the Node side also
      // refuses non-allowlisted realms.
      if (!allowedRealms.includes(r)) return;
      // Idempotency guard — if this script ran on a previous document,
      // the exposed functions are now bound to that document's context
      // and we don't need to start another poll loop here.
      const w = window as unknown as {
        __tideCarveOutPolling?: boolean;
        __captureCarveOut?: (cap: { sessKeySerialized: string }) => void;
        __captureCarveOutError?: (err: { reason: string }) => void;
        __tideEnclave?: {
          SessionKey?: {
            get_private_component?: () => {
              Serialize?: () => { ToString?: () => string };
            };
          };
        };
      };
      if (w.__tideCarveOutPolling) return;
      w.__tideCarveOutPolling = true;

      const START = Date.now();
      const BUDGET_MS = 60_000;
      let observedOnce = false;

      const interval = setInterval(() => {
        try {
          const enc = w.__tideEnclave;
          if (enc && enc.SessionKey) {
            observedOnce = true;
            let sessKeySerialized = "";
            try {
              const priv = enc.SessionKey.get_private_component?.();
              const ser  = priv?.Serialize?.();
              const s    = ser?.ToString?.();
              if (typeof s === "string") sessKeySerialized = s;
            } catch (e) {
              clearInterval(interval);
              w.__captureCarveOutError?.({
                reason: `SessionKey extract: ${(e as Error).message}`,
              });
              return;
            }
            if (sessKeySerialized) {
              clearInterval(interval);
              w.__captureCarveOut?.({ sessKeySerialized });
              return;
            }
            // SessionKey present on the enclave but the accessor returned
            // a non-string — surface as an error so Node distinguishes
            // this from "never observed".
            clearInterval(interval);
            w.__captureCarveOutError?.({
              reason: "enclave SessionKey present but extract returned non-string",
            });
            return;
          }
        } catch (e) {
          clearInterval(interval);
          try {
            w.__captureCarveOutError?.({
              reason: `poll: ${(e as Error).message}`,
            });
          } catch {
            // exposed fn not yet bound; nothing we can do
          }
          return;
        }
        if (Date.now() - START > BUDGET_MS) {
          clearInterval(interval);
          if (!observedOnce) {
            try {
              w.__captureCarveOutError?.({
                reason: "enclave never observed before timeout",
              });
            } catch {
              // exposed fn not yet bound; nothing we can do
            }
          }
        }
      }, 50);
    },
    { realm, allowedRealms: Array.from(ALLOWLIST_CARVE_OUT_REALMS) },
  );

  const dispose = () => {
    if (settled) return;
    settled = true;
    // Reject with a sentinel so any awaiter sees it as a controlled
    // shutdown, not a leaked unhandled rejection.
    const e = new Error("carve-out pump disposed") as Error & { reason: string };
    e.reason = "disposed";
    reject(e);
  };

  return { capturedPromise, dispose };
}

export async function awaitFlow(
  harnessUrl: string,
  state: string,
  timeoutMs: number,
): Promise<OidcAwaitResponse> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${harnessUrl}/warmup/oidc/await/${encodeURIComponent(state)}`, {
      signal: ctrl.signal,
    });
    const json = (await res.json()) as OidcAwaitResponse;
    if (!res.ok || !json?.ok) {
      throw new Error(
        `/warmup/oidc/await/${state.slice(0, 8)}… returned ${res.status}: ${json?.code ?? "?"} ${json?.message ?? ""}`,
      );
    }
    return json;
  } finally {
    clearTimeout(timer);
  }
}

// Base64URL-decode the middle segment of a JWT and parse it. Throws on
// malformed input. We do NOT trust this output for any security
// decision — it's used purely to extract the vuid claim. The harness
// never validates the JWT.
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  if (parts.length < 2) throw new Error("doken does not look like a JWT (no dots)");
  const payload = parts[1];
  // base64url → base64
  const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
  // pad to multiple of 4
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const json = Buffer.from(padded, "base64").toString("utf8");
  return JSON.parse(json) as Record<string, unknown>;
}

// vuid extraction strategy (from Round-3 brief): prefer preferred_username
// if it looks like a 64-char hex string (the Tide first-broker-login
// auto-username pattern); otherwise fall back to sub. Return both the
// chosen value and which claim it came from, for the warm-up summary.
const HEX64 = /^[a-f0-9]{64}$/;

export interface VuidPick {
  vuid:  string;
  claim: "preferred_username" | "sub" | "fallback-userId";
}

export function pickVuid(payload: Record<string, unknown>, userId: string): VuidPick {
  const pref = payload["preferred_username"];
  if (typeof pref === "string" && HEX64.test(pref)) {
    return { vuid: pref, claim: "preferred_username" };
  }
  const sub = payload["sub"];
  if (typeof sub === "string" && sub.length > 0) {
    return { vuid: sub, claim: "sub" };
  }
  // Last-resort: we have no usable claim. Fall back to userId so the
  // fixture still validates, but mark the source so an operator notices.
  return { vuid: userId, claim: "fallback-userId" };
}

// Phase enum so captureUserFixture() knows whether a debug-dump is
// safe (pre-fill) or unsafe (post-fill — the page may be holding the
// user's typed password in a visible <input>).
//
// `await-callback` is the Round-7 addition: a timeout waiting for the
// /callback redirect after the Sign In click. It's post-fill, so
// debug-dump is unsafe (the SWE form may still have the typed
// password in its shadow <input>).
type SwePhase =
  | "selector-username"
  | "selector-password"
  | "filled"
  | "submitted"
  | "await-callback";

class SweLoginError extends Error {
  readonly phase: SwePhase;
  constructor(phase: SwePhase, message: string) {
    super(message);
    this.name  = "SweLoginError";
    this.phase = phase;
  }
}

// Drive the SWE login form. Errors from this function are SweLoginErrors
// tagged with the phase the failure happened in. captureUserFixture()
// uses the phase to decide whether a debug-dump is safe.
// Fill the SWE login form (username + password). Returns the password
// host Locator so a caller that wants to drive Enter-as-submit fallback
// (sweClickSignIn) doesn't have to re-resolve it. R22: split out of the
// monolithic driveSweLogin so the load-test driver can time form-fill
// and sign-in click as separate phases without reimplementing the
// shadow-DOM-aware drive primitives.
export async function sweFormFill(
  page: import("playwright").Page,
  user: LoadTestUser,
  navTimeoutMs: number,
): Promise<import("playwright").Locator> {
  // Step 1: locate username host (shadow-DOM-aware).
  const userHost = await waitForCustomInputHost(
    page,
    SWE_SELECTORS.usernameHost,
    navTimeoutMs,
  );
  if (!userHost) {
    throw new SweLoginError(
      "selector-username",
      `SWE login form: ${SWE_SELECTORS.usernameHost} did not mount with a shadow <input> within ${navTimeoutMs}ms`,
    );
  }

  // Step 2: locate password host. Single-screen form — both fields are
  // present together. We resolve both up front so a missing password
  // field surfaces as a selector failure (safe to dump) rather than
  // failing after we've typed the password.
  const pwHost = await waitForCustomInputHost(
    page,
    SWE_SELECTORS.passwordHost,
    navTimeoutMs,
  );
  if (!pwHost) {
    throw new SweLoginError(
      "selector-password",
      `SWE login form: ${SWE_SELECTORS.passwordHost} did not mount with a shadow <input> within ${navTimeoutMs}ms`,
    );
  }

  // Step 3: fill username.
  await fillCustomInput(userHost, user.userId);

  // Step 4: fill password.
  // SECURITY: fillCustomInput() is the ONE sanctioned egress for the
  // password. Do NOT add logging that captures pwHost, user.password,
  // or any surrounding form HTML downstream. From this point on, the
  // page DOM contains the typed password — a debug-dump is unsafe.
  await fillCustomInput(pwHost, user.password);

  return pwHost;
}

// Click Sign In with the same fallback policy as the original
// driveSweLogin. R22: extracted so the load-test driver can record the
// click latency as its own phase.
export async function sweClickSignIn(
  page: import("playwright").Page,
  pwHost: import("playwright").Locator,
  navTimeoutMs: number,
): Promise<void> {
  // Step 5: click Sign In. The trigger is a clickable <div> — see
  // resolveSignInTrigger() for the selector rationale.
  const signIn = await resolveSignInTrigger(page, Math.min(5_000, navTimeoutMs));
  try {
    if (signIn) {
      await signIn.click();
    } else {
      // Defence-in-depth: pressing Enter while focus is in the
      // password shadow <input> SHOULD trigger form submit on most
      // implementations. If the click selector failed, fall back to
      // Enter via the host (Playwright forwards keyboard to the host's
      // active element, which is the focused shadow <input>).
      await pwHost.press("Enter").catch(() => undefined);
    }
  } catch (e) {
    throw new SweLoginError(
      "submitted",
      `SWE login: failed to trigger sign-in: ${(e as Error).message}`,
    );
  }
}

export async function driveSweLogin(
  page: import("playwright").Page,
  user: LoadTestUser,
  navTimeoutMs: number,
): Promise<void> {
  const pwHost = await sweFormFill(page, user, navTimeoutMs);
  await sweClickSignIn(page, pwHost, navTimeoutMs);
}

// Sanitize a string for use in a filename. Allows [a-zA-Z0-9._-], maps
// everything else to '_'. We slice to 64 chars so a malicious userId
// can't generate pathologically long paths.
function sanitiseForFilename(s: string): string {
  const cleaned = s.replace(/[^a-zA-Z0-9._-]/g, "_");
  return cleaned.slice(0, 64) || "unknown";
}

// Redact <input value="..."> attributes and any explicit <input
// type="password" ...> elements from an HTML string. Used by the
// debug-dump path. We deliberately keep this REGEX-based rather than
// HTML-parsing: it must succeed even on truncated / weird HTML.
function redactHtmlValues(html: string): string {
  let out = html;
  // Strip value="..." (both single and double quotes).
  out = out.replace(/(\s)value\s*=\s*"[^"]*"/gi, '$1value="<REDACTED>"');
  out = out.replace(/(\s)value\s*=\s*'[^']*'/gi, "$1value='<REDACTED>'");
  // Whole password-input elements get inner content scrubbed too.
  out = out.replace(
    /(<input\b[^>]*\btype\s*=\s*["']password["'][^>]*>)/gi,
    "<input type=\"password\" value=\"<REDACTED>\">",
  );
  return out;
}

interface DebugDumpOpts {
  page:   import("playwright").Page;
  userId: string;
  reason: string;
}

// Write a redacted HTML + PNG snapshot of the current page state to
// /tmp/warmup-fail-<userId>.{html,png}. Gated by WARMUP_DEBUG_DUMP=true
// and ONLY called for pre-fill (selector) failures, so neither the
// HTML nor the screenshot can contain the typed password.
async function maybeDebugDump(opts: DebugDumpOpts): Promise<string | null> {
  if ((process.env.WARMUP_DEBUG_DUMP ?? "false").toLowerCase() !== "true") {
    return null;
  }
  const safeId  = sanitiseForFilename(opts.userId);
  const htmlOut = `/tmp/warmup-fail-${safeId}.html`;
  const pngOut  = `/tmp/warmup-fail-${safeId}.png`;
  try {
    mkdirSync(dirname(htmlOut), { recursive: true });
    let html = "";
    try {
      html = await opts.page.content();
    } catch {
      html = "<!-- page.content() unavailable -->";
    }
    const redacted =
      `<!-- warmup debug dump\n` +
      `     reason: ${opts.reason}\n` +
      `     url:    ${opts.page.url()}\n` +
      `     time:   ${new Date().toISOString()}\n` +
      `-->\n` +
      redactHtmlValues(html);
    writeFileSync(htmlOut, redacted, "utf8");
    await opts.page.screenshot({ path: pngOut, fullPage: true }).catch(() => undefined);
    return `${htmlOut} (+ ${pngOut})`;
  } catch {
    return null;
  }
}

export async function captureUserFixture(opts: CaptureOptions): Promise<UserFixture> {
  const awaitTimeoutMs = opts.awaitTimeoutMs ?? DEFAULT_AWAIT_TIMEOUT_MS;
  const navTimeoutMs = opts.navTimeoutMs ?? DEFAULT_NAV_TIMEOUT_MS;

  // 1. Begin the OIDC flow on the harness.
  const begin = await beginFlow(opts.harnessUrl, opts.user.userId);

  const page = await opts.context.newPage();
  page.setDefaultTimeout(navTimeoutMs);
  page.setDefaultNavigationTimeout(navTimeoutMs);

  // 2-pre. Install the carve-out pump BEFORE the first navigation. The
  //        init script must be registered before `page.goto(authUrl)` so
  //        it runs in the JS context of every document the page loads,
  //        including the SWE origin where `__tideEnclave` is populated.
  //        The pump itself is realm-gated in two places (init script
  //        early-return + Node-side exposed-function early-return) so
  //        documents loaded for non-allowlisted realms are a no-op.
  //
  //        R13: this replaces the post-Sign-In `extractCarveOutInPage()`
  //        approach, which used `waitForFunction` + a Node-side
  //        `page.evaluate()` that raced the SWE→TideCloak→/callback
  //        redirect chain. The pump observes the enclave in-page and
  //        ships the capture material across the Playwright boundary
  //        via `exposeFunction` — the page-side call returns immediately
  //        so a redirect firing nanoseconds later doesn't lose the
  //        capture.
  const pump = await installCarveOutPump(page, opts.realm);
  // Surface unhandled rejections silently; we await the promise below
  // when we want it, but the `dispose()` path may also reject and we
  // don't want Node to warn about an unhandled rejection in the
  // failure / non-allowlisted-realm case.
  pump.capturedPromise.catch(() => undefined);

  // 2a. Nav tracing (Round 7). Operators need visibility into where
  //     the flow stalls between Sign In and /callback — Round 4 QA's
  //     `waitForURL: Timeout 120000ms exceeded` told them nothing
  //     about whether the browser was still on the SWE, parked on a
  //     TideCloak interstitial, or had reached the callback host but
  //     missed our predicate. We log one line per MAIN-frame nav,
  //     origin + pathname only — the query string is stripped because
  //     it can carry `code=`, `state=`, gVVK, voucherURL, and other
  //     Tide-sensitive params.
  //
  //     `lastMainFrameUrl` is consumed by the catch block below to
  //     enrich an await-callback timeout with the final URL the
  //     browser actually reached.
  let lastMainFrameUrl = "";
  const navTraceHandler = (frame: import("playwright").Frame) => {
    if (frame !== page.mainFrame()) return;
    const raw = frame.url();
    let stripped = raw;
    try {
      const u = new URL(raw);
      stripped = `${u.origin}${u.pathname}`;
    } catch {
      // about:blank, data: URLs, etc. — log as-is, no query to leak.
    }
    lastMainFrameUrl = stripped;
    // eslint-disable-next-line no-console
    console.log(`[warmup] nav: ${stripped}`);
  };
  page.on("framenavigated", navTraceHandler);

  // 2b. Set up Path-α sniffer: the first frame that navigates to a
  //     sork*.tideprotocol.com URL carrying gVVK / voucherURL in the
  //     query string is what the brief calls the "SWE URL". We forward
  //     every matching URL to the sniffer (which de-dupes per field on
  //     its side) rather than just the first — defence-in-depth in case
  //     a downstream navigation carries one param but not the other.
  if (opts.onSweUrl) {
    const handler = (frame: import("playwright").Frame) => {
      const url = frame.url();
      if (/tideprotocol\.com/.test(url) && /[?&](gVVK|voucherURL)=/.test(url)) {
        try {
          opts.onSweUrl!(url);
        } catch {
          // best-effort
        }
      }
    };
    page.on("framenavigated", handler);
  }

  try {
    // 3. Navigate the browser to the authorize URL.
    await page.goto(begin.authUrl, { waitUntil: "domcontentloaded" });

    // 4. Drive the SWE login.
    await driveSweLogin(page, opts.user, navTimeoutMs);

    // 4b. Option B carve-out — realm-gated, in-page pump (R13).
    //
    //     The pump was installed BEFORE page.goto() up at step 2-pre.
    //     It polls `__tideEnclave` in-page and ships the SessionKey to
    //     Node via `exposeFunction` as soon as it appears. We just await
    //     the capture here (with the same `awaitTimeoutMs` ceiling we
    //     use for /callback) and POST. R15: tideDoken is no longer part
    //     of this capture — it now ships on TideCloak's /token response
    //     as a sibling `doken` field and the harness extracts it server-
    //     side in exchangeCodeForToken().
    //
    //     If the realm is NOT in ALLOWLIST_CARVE_OUT_REALMS, the pump
    //     is a no-op (both the init script and the Node-side exposed
    //     functions short-circuit). We don't need to await anything.
    //     No log of the realm value beyond the allowlist-match decision.
    if (isCarveOutRealm(opts.realm)) {
      // Race the capture against the awaitTimeoutMs budget. If the
      // pump completes first (it should — the enclave is populated
      // seconds before /callback fires), we POST. If the budget
      // expires first, we drop through with a diagnostic and let
      // runSign refuse downstream.
      let capTimer: ReturnType<typeof setTimeout> | undefined;
      const timeoutMarker = Symbol("carve-out-timeout");
      const timeoutPromise = new Promise<typeof timeoutMarker>((resolve) => {
        capTimer = setTimeout(() => resolve(timeoutMarker), Math.min(60_000, awaitTimeoutMs));
      });
      let capResult: CarveOutCapture | typeof timeoutMarker | { error: Error & { reason?: string } };
      try {
        const winner = await Promise.race<CarveOutCapture | typeof timeoutMarker>([
          pump.capturedPromise,
          timeoutPromise,
        ]);
        capResult = winner;
      } catch (e) {
        capResult = { error: e as Error & { reason?: string } };
      } finally {
        if (capTimer) clearTimeout(capTimer);
      }

      if (capResult === timeoutMarker) {
        // We won the race against the pump — no resolve, no in-page
        // error fired within budget. Emit the explicit diagnostic QA
        // asked for and let runSign refuse downstream.
        // eslint-disable-next-line no-console
        console.warn(
          "[warmup] carve-out: enclave never observed before timeout",
        );
      } else if (typeof capResult === "object" && capResult !== null && "error" in capResult) {
        // The in-page side called __captureCarveOutError. Surface the
        // reason so QA can distinguish "never observed" from "observed
        // but extract failed". The reason string is constructed in the
        // init script — no key material is included.
        const reason = capResult.error.reason ?? capResult.error.message;
        // eslint-disable-next-line no-console
        console.warn(
          `[warmup] carve-out: in-page extract failed: ${reason}`,
        );
      } else {
        // Happy path — SessionKey captured. Log presence (Y) only;
        // never log length or value. R15: tideDoken is no longer part
        // of the in-page capture, so the log message reflects the
        // now-narrower scope.
        const cap = capResult;
        try {
          await postCarveOutCapture(opts.harnessUrl, begin.state, {
            sessKeySerialized: cap.sessKeySerialized,
          });
          // eslint-disable-next-line no-console
          console.log("[warmup] carve-out: sessKey captured (Y)");
        } catch (e) {
          // We do NOT abort the warm-up on carve-out POST failure —
          // the OIDC access_token + tideDoken capture is independent
          // (both ship on the /token response). The user will simply
          // lack sessKeySerialized in their fixture; their runSign call
          // will refuse loudly. Log a brief diagnostic (no key material).
          // eslint-disable-next-line no-console
          console.warn(
            `[warmup] carve-out POST failed for ${opts.user.userId}: ${(e as Error).message}`,
          );
        }
      }
    } else {
      // Realm refusal — deliberate. Make it visible in logs (without
      // disclosing what the operator would have to do to enable it).
      // eslint-disable-next-line no-console
      console.log(
        `[warmup] sessKey capture REFUSED — realm not in ALLOWLIST_CARVE_OUT_REALMS`,
      );
    }

    // 5. Wait for redirect to <callbackOrigin>/callback?code=...&state=...
    //    The harness server is in the same process group as us; once it
    //    receives the callback it resolves the pending /await promise.
    //
    //    Round 7: on timeout, capture the final main-frame URL
    //    (origin+pathname only — query stripped) and wrap the error in
    //    a SweLoginError tagged with phase='await-callback'. This makes
    //    the failure self-diagnostic without a debug-dump (post-fill,
    //    so dump is unsafe).
    try {
      // R11: waitUntil="domcontentloaded" — softer than the default
      // "load", which the Round-10 QA flake (120s timeout) hit waiting
      // for some slow sub-resource of the /callback page. We only need
      // the URL predicate to match and the DOM to be parsed; the
      // /callback handler in server.ts itself does no heavy work, and
      // waitForURL doesn't need 'load' for our subsequent `awaitFlow`
      // long-poll.
      await page.waitForURL(
        (url) =>
          url.origin === opts.callbackOrigin &&
          url.pathname === "/callback" &&
          (url.searchParams.has("code") || url.searchParams.has("error")),
        { timeout: awaitTimeoutMs, waitUntil: "domcontentloaded" },
      );
    } catch (e) {
      // Prefer the live page URL at the moment of failure; fall back
      // to the last main-frame URL the tracer saw if page.url() throws
      // (e.g. page already closed). Strip query in both cases.
      let finalUrl = lastMainFrameUrl;
      try {
        const u = new URL(page.url());
        finalUrl = `${u.origin}${u.pathname}`;
      } catch {
        // keep lastMainFrameUrl
      }
      const rawMsg = e instanceof Error ? e.message : String(e);
      throw new SweLoginError(
        "await-callback",
        `${rawMsg}. Final URL: ${finalUrl || "<unknown>"}`,
      );
    }

    // 6. Long-poll the harness for the captured token.
    const result = await awaitFlow(opts.harnessUrl, begin.state, awaitTimeoutMs);
    if (!result.doken) {
      throw new Error("await flow returned ok but no doken field");
    }

    // 7. Decode the JWT and extract vuid.
    const payload = decodeJwtPayload(result.doken);
    const { vuid } = pickVuid(payload, opts.user.userId);

    // 8. Compute dokenExpiresAt if we have expires_in.
    const dokenExpiresAt =
      typeof result.expiresInSeconds === "number"
        ? new Date(Date.now() + result.expiresInSeconds * 1000).toISOString()
        : undefined;

    const fixture: UserFixture = {
      userId: opts.user.userId,
      vuid,
      doken: result.doken,
    };
    if (typeof result.refreshToken === "string") {
      fixture.refreshToken = result.refreshToken;
    }
    if (dokenExpiresAt) {
      fixture.dokenExpiresAt = dokenExpiresAt;
    }
    // Option B carve-out: `sessKeySerialized` is present only when the
    // realm gate let us capture; null when no POST landed (e.g. capture
    // failed or realm refused) — we omit it rather than write `null`.
    //
    // R15: `tideDoken` is now sourced from the token-exchange response
    // (TideCloak attaches it as a sibling `doken` field on /token), so
    // it ships on /warmup/oidc/await/:state regardless of whether the
    // in-page SessionKey pump succeeded. We still gate the fixture
    // assignment on a non-empty string so a TideCloak that didn't issue
    // one results in an omitted field — runSign will refuse downstream.
    if (typeof result.sessKeySerialized === "string" && result.sessKeySerialized.length > 0) {
      fixture.sessKeySerialized = result.sessKeySerialized;
    }
    if (typeof result.tideDoken === "string" && result.tideDoken.length > 0) {
      fixture.tideDoken = result.tideDoken;
    }
    return fixture;
  } catch (e: unknown) {
    // SECURITY: scrub the password from any error message before
    // re-throwing. Playwright sometimes echoes the form HTML or the
    // failing selector context in error messages.
    const raw = e instanceof Error ? e.message : String(e);
    let withDump = raw;

    // Debug-dump path. ONLY safe on pre-fill (selector) failures —
    // post-fill failures may leave the typed password in the DOM /
    // screenshot. captureUserFixture() never overwrites this rule.
    const phase: SwePhase | undefined =
      e instanceof SweLoginError ? e.phase : undefined;
    const isPreFillSelectorFailure =
      phase === "selector-username" || phase === "selector-password";
    if (isPreFillSelectorFailure) {
      const dumped = await maybeDebugDump({
        page,
        userId: opts.user.userId,
        reason: raw,
      });
      if (dumped) {
        withDump = `${raw} [debug-dump: ${dumped}]`;
      }
    }

    throw new Error(redact(withDump, opts.user.password));
  } finally {
    // Resolve/reject the pump promise if it's still pending so any
    // late in-page callback is a no-op and we don't leak handlers.
    pump.dispose();
    await page.close().catch(() => {});
  }
}
