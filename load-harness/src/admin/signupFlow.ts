//
// SWE Sign-Up driver — Playwright flow that creates a new user end-to-end.
//
// Discovered via /tmp/r1-provision-probe.mjs against staging tide-metrics-load:
//
//   1. Browser → TideCloak /protocol/openid-connect/auth (with kc_idp_hint=tide)
//                → SWE on sork1 (cmkOnly type)
//   2. Sign-in screen renders. Click "Create an account" link (`p.text` with
//      that text) to switch to sign-up.
//   3. Sign-up step 1 (username + password + repeat_password) →
//      click `#sign_up-button` Continue → step 2.
//   4. Sign-up step 2 (email) →
//      click `#sign_up_email-button` Continue → the SWE runs dKeyGenerationFlow:
//      cohort fetch + 3 voucher POSTs + 5 ORK Convert calls + broker callback.
//      The browser then navigates to TideCloak's first-broker-login
//      `Update Account Information` form.
//   5. Update Account Information: fill firstName + lastName (email is usually
//      pre-populated by SWE; username field is auto-vuid and read-only-ish).
//      Submit → OIDC redirects to <callbackOrigin>/callback?code=...
//   6. The /callback hits the harness, which exchanges the code with TideCloak.
//      Token exchange FAILS with TIDE-TIDECLOAK-TOKEN-NO_USER_CONTEXT (R19 gate);
//      this is expected for the cmkOnly load-test path — we don't need the
//      access_token, only the fact that we reached /callback with a code at all.
//
// Voucher cost per Sign-Up: ~3 voucher draws (observed during the probe).
//
// SECURITY:
//   * password is sent to the SWE via the same setter+dispatch pattern as the
//     sign-in driver (see warmup/oidc.ts:fillCustomInput). Never logged.
//   * email is operator-visible by design.
//   * No screenshots are taken on the sign-up screen post-fill (the password
//     would be in the DOM).
//

import type { BrowserContext, Page, Locator } from "playwright";
import type { LoadTestUser } from "../warmup/types.js";

// ---------------------------------------------------------------------------
// Selectors
// ---------------------------------------------------------------------------

export const SIGNUP_SELECTORS = {
  // Sign-in screen marker (used to confirm SWE rendered before switching).
  signInUsernameHost:     "custom-input#sign_in-input_name",
  // Switch to sign-up: the SWE renders the link as <p class="text"> with
  // the literal "Create an account" text. There can be multiple matches
  // across hidden screens; first() is on the sign-in screen.
  createAccountLink:      "p.text",
  createAccountLinkText:  "Create an account",

  // Step 1 — username + password + repeat.
  step1UsernameHost:      "custom-input#sign_up-input_username",
  step1PasswordHost:      "custom-input#sign_up-input_password",
  step1RepeatHost:        "custom-input#sign_up-input_repeat_password",
  step1ContinueButton:    "#sign_up-button",

  // Step 2 — email.
  step2EmailHost:         "custom-input#sign_up-email-input-1",
  step2ContinueButton:    "#sign_up_email-button",

  // First-broker-login Update Account Information (plain Keycloak HTML).
  fblUsername:            "input#username",
  fblEmail:               "input#email",
  fblFirstName:           "input#firstName",
  fblLastName:            "input#lastName",
  fblSubmit:              "input[type=submit], button[type=submit]",
} as const;

// ---------------------------------------------------------------------------
// Shadow-DOM primitives (mirror warmup/oidc.ts)
// ---------------------------------------------------------------------------

async function fillCustomInput(host: Locator, value: string): Promise<void> {
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

async function waitForCustomInputHost(
  page: Page,
  hostSelector: string,
  timeoutMs: number,
): Promise<Locator | null> {
  const host = page.locator(hostSelector).first();
  try {
    await host.waitFor({ state: "visible", timeout: timeoutMs });
  } catch {
    // visible may fail even when interactable; fall back to attached.
    try {
      await host.waitFor({ state: "attached", timeout: 5_000 });
    } catch {
      return null;
    }
  }
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

async function clickVisibleButton(
  page: Page,
  idSelector: string,
  timeoutMs: number,
): Promise<void> {
  const loc = page.locator(idSelector);
  await loc.waitFor({ state: "visible", timeout: timeoutMs });
  await loc.click({ timeout: timeoutMs });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface SignUpResult {
  ok:           boolean;
  step:         string;          // last completed phase marker
  callbackUrl?: string;          // /callback?code=... when reached
  errorMessage?: string;
  voucherDraws:  number;         // count observed via network listener
  cohortConvertCount: number;    // count of /Authentication/Auth/Convert
  durationMs:    number;
}

export interface SignUpFlowOpts {
  context:        BrowserContext;
  authUrl:        string;
  callbackOrigin: string;        // e.g. http://localhost:3000
  user:           LoadTestUser;
  email:          string;
  firstName?:     string;        // default "Load"
  lastName?:      string;        // default user.userId
  navTimeoutMs?:  number;        // default 60_000
  totalTimeoutMs?:number;        // default 240_000
  /** Caller-supplied logger so we can prefix per-user. */
  log?: (msg: string) => void;
}

const DEFAULT_NAV_TIMEOUT_MS   = 60_000;
const DEFAULT_TOTAL_TIMEOUT_MS = 240_000;

function redactPwd(s: string, password: string): string {
  if (!password || password.length < 3) return s;
  const enc = encodeURIComponent(password);
  return s.split(password).join("[REDACTED]").split(enc).join("[REDACTED]");
}

export async function driveSignUpFlow(opts: SignUpFlowOpts): Promise<SignUpResult> {
  const log = opts.log ?? (() => {});
  const navTimeoutMs = opts.navTimeoutMs ?? DEFAULT_NAV_TIMEOUT_MS;
  const totalTimeoutMs = opts.totalTimeoutMs ?? DEFAULT_TOTAL_TIMEOUT_MS;
  const startedAt = Date.now();

  const page = await opts.context.newPage();
  page.setDefaultTimeout(navTimeoutMs);
  page.setDefaultNavigationTimeout(navTimeoutMs);

  // Network counters for visibility into voucher / cohort activity.
  let voucherDraws = 0;
  let cohortConvertCount = 0;
  page.on("response", (res) => {
    const url = res.url();
    if (/\/tidevouchers\//.test(url) && res.request().method() === "POST") {
      voucherDraws++;
    }
    if (/\/Authentication\/Auth\/Convert/.test(url)) {
      cohortConvertCount++;
    }
  });

  let step = "begin";
  try {
    await page.goto(opts.authUrl, { waitUntil: "domcontentloaded", timeout: navTimeoutMs });
    step = "authorize-navigated";

    // 1. Wait for sign-in.
    const signInHost = await waitForCustomInputHost(page, SIGNUP_SELECTORS.signInUsernameHost, 30_000);
    if (!signInHost) throw new Error("sign-in screen never rendered");
    step = "sign-in-screen";

    // 2. Switch to sign-up.
    await page.locator(SIGNUP_SELECTORS.createAccountLink)
      .filter({ hasText: SIGNUP_SELECTORS.createAccountLinkText })
      .first()
      .click({ timeout: 5_000 });
    step = "create-account-clicked";

    // 3. Step 1 — username + password + repeat.
    const userHost   = await waitForCustomInputHost(page, SIGNUP_SELECTORS.step1UsernameHost, 10_000);
    const pwdHost    = await waitForCustomInputHost(page, SIGNUP_SELECTORS.step1PasswordHost, 5_000);
    const repeatHost = await waitForCustomInputHost(page, SIGNUP_SELECTORS.step1RepeatHost,   5_000);
    if (!userHost || !pwdHost || !repeatHost) throw new Error("sign-up step 1 hosts missing");
    await fillCustomInput(userHost,   opts.user.userId);
    await fillCustomInput(pwdHost,    opts.user.password);
    await fillCustomInput(repeatHost, opts.user.password);
    await clickVisibleButton(page, SIGNUP_SELECTORS.step1ContinueButton, 10_000);
    step = "step1-submitted";

    // 4. Step 2 — email.
    const emailHost = await waitForCustomInputHost(page, SIGNUP_SELECTORS.step2EmailHost, 30_000);
    if (!emailHost) throw new Error("sign-up step 2 email host missing");
    await fillCustomInput(emailHost, opts.email);
    await clickVisibleButton(page, SIGNUP_SELECTORS.step2ContinueButton, 10_000);
    step = "step2-submitted";
    log(`SWE bootstrap in progress (cohort+voucher+Convert)…`);

    // 5. First-broker-login Update Account Information page.
    try {
      await page.locator("input#email, input#firstName, input#username")
        .first()
        .waitFor({ state: "visible", timeout: 90_000 });
    } catch (e) {
      throw new Error(`first-broker-login form did not appear: ${(e as Error).message}`);
    }
    step = "fbl-form-visible";

    const setIfVisible = async (sel: string, val: string): Promise<void> => {
      const loc = page.locator(sel).first();
      if ((await loc.count()) === 0) return;
      if (!(await loc.isVisible().catch(() => false))) return;
      try {
        await loc.fill(val);
      } catch {
        await loc.evaluate((el, v) => {
          const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
          desc?.set?.call(el, v);
          el.dispatchEvent(new Event("input",  { bubbles: true }));
          el.dispatchEvent(new Event("change", { bubbles: true }));
        }, val);
      }
    };
    await setIfVisible(SIGNUP_SELECTORS.fblEmail,     opts.email);
    await setIfVisible(SIGNUP_SELECTORS.fblFirstName, opts.firstName ?? "Load");
    await setIfVisible(SIGNUP_SELECTORS.fblLastName,  opts.lastName  ?? opts.user.userId);

    const submit = page.locator(SIGNUP_SELECTORS.fblSubmit).first();
    try {
      await submit.click({ timeout: 5_000 });
    } catch {
      await page.keyboard.press("Enter").catch(() => undefined);
    }
    step = "fbl-submitted";

    // 6. Wait for /callback?code=... or ?error=...
    const callbackDeadline = Math.max(60_000, totalTimeoutMs - (Date.now() - startedAt));
    await page.waitForURL(
      (url) =>
        url.origin === opts.callbackOrigin &&
        url.pathname === "/callback" &&
        (url.searchParams.has("code") || url.searchParams.has("error")),
      { timeout: callbackDeadline, waitUntil: "domcontentloaded" },
    );
    step = "callback-reached";
    const callbackUrl = page.url();
    return {
      ok: true,
      step,
      callbackUrl,
      voucherDraws,
      cohortConvertCount,
      durationMs: Date.now() - startedAt,
    };
  } catch (e) {
    const raw = e instanceof Error ? e.message : String(e);
    const scrubbed = redactPwd(raw, opts.user.password);
    return {
      ok: false,
      step,
      errorMessage: scrubbed,
      voucherDraws,
      cohortConvertCount,
      durationMs: Date.now() - startedAt,
    };
  } finally {
    await page.close().catch(() => undefined);
  }
}
