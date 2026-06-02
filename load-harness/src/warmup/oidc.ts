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

async function beginFlow(harnessUrl: string, userId: string): Promise<OidcBeginResponse> {
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

async function awaitFlow(
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
async function driveSweLogin(
  page: import("playwright").Page,
  user: LoadTestUser,
  navTimeoutMs: number,
): Promise<void> {
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
      await page.waitForURL(
        (url) =>
          url.origin === opts.callbackOrigin &&
          url.pathname === "/callback" &&
          (url.searchParams.has("code") || url.searchParams.has("error")),
        { timeout: awaitTimeoutMs },
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
    await page.close().catch(() => {});
  }
}
