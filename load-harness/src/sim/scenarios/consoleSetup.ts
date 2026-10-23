// S3 through the real tide-console create-realm wizard, driven in a browser (local or remote Azure).
// This is the admin path: open the console, log in on the Keycloak form, fill the wizard and submit.
//
// Scope note: the console wizard, after provisioning the vendor key, goes on to enable QEA, create
// an admin user and PAUSE for a human to link a Tide account in the enclave (an interactive step a
// load driver cannot complete). The workspace-setup load from the incident (createRealm ->
// setUpTideRealm -> CreateFreeTierLicense/FinalizeVendor across the ORKs + payer vouchers via the
// Stripe stub) all happens in the wizard's first step, BEFORE that pause. So this driver treats the
// `setUpTideRealm` call resolving (CREATED, or a terminal error) as the measured outcome, records
// how far the wizard got, and stops at the link-tide pause. It adds no steps of its own.

import type { Page } from "playwright";
import type { BrowserHost } from "./browser.js";
import type { AdminCreds } from "../admin.js";
import type { OpContext, OpOutcome } from "../engine.js";
import type { ManifestWriter } from "../sink.js";
import { matchSignatures } from "../signatures.js";
import { setupNames } from "./setup.js";

export interface ConsoleSetupDeps {
  host: BrowserHost;
  tcBase: string;
  runId: string;
  emailDomain: string;
  creds: AdminCreds;
  manifest: ManifestWriter;
  retries: number;          // extra Retry clicks after the first failure
  log: (s: string) => void;
}

const SETUP_CALL = /\/vendorResources\/setUpTideRealm\b/;
const VENDOR_CALL = /\/vendorResources\/|\/tide-admin\/|\/admin\/realms\/[^/]+\/(iga|users|clients)\b/;

// Pull a Tide error code out of a response body.
function errorCode(body: string, status: number): string {
  const m = /"code"\s*:\s*"([A-Z0-9_\-]+)"/.exec(body) ?? /(TIDE-[A-Z0-9_\-]+)/.exec(body);
  if (m) return m[1];
  const sig = matchSignatures(body)[0];
  return sig ? sig.id : `HTTP_${status}`;
}

interface SetupWatch {
  calls: Array<{ status: number; body: string }>;
  vendorErrors: string[];
}

// Record setUpTideRealm responses and any 4xx/5xx from the related vendor/IGA calls.
function watchSetup(page: Page): SetupWatch {
  const w: SetupWatch = { calls: [], vendorErrors: [] };
  page.on("response", async (res) => {
    const url = res.url();
    const isSetup = SETUP_CALL.test(url);
    if (!isSetup && !(VENDOR_CALL.test(url) && res.status() >= 400)) return;
    let body = "";
    try { body = (await res.text()).slice(0, 400); } catch { /* gone */ }
    if (isSetup) w.calls.push({ status: res.status(), body });
    else if (w.vendorErrors.length < 6) w.vendorErrors.push(`HTTP ${res.status()} ${new URL(url).pathname}: ${body}`);
  });
  return w;
}

async function loginIfNeeded(page: Page, creds: AdminCreds, tcBase: string, navTimeoutMs: number): Promise<void> {
  // The console redirects to the Keycloak login form when there is no session on this context.
  const user = page.locator("#username");
  try {
    await user.waitFor({ state: "visible", timeout: 8_000 });
  } catch {
    return; // already authenticated on this context
  }
  await user.fill(creds.user);
  // The password is typed into the form and never logged.
  await page.locator("#password").fill(creds.password);
  await page.locator("#kc-login, input[type=submit], button[type=submit]").first().click();
  await page.waitForURL((u) => u.href.startsWith(tcBase) && !/\/openid-connect\/auth/.test(u.href), { timeout: navTimeoutMs }).catch(() => undefined);
}

// Wait until setUpTideRealm resolves, the wizard shows the setUpTideRealm step failed, or the
// wizard reaches the human link-tide pause (which means provisioning succeeded).
async function waitForSetupOutcome(page: Page, w: SetupWatch, timeoutMs: number): Promise<"created" | "failed" | "reached-link" | "timeout"> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const last = w.calls[w.calls.length - 1];
    if (last) {
      if (last.status === 200 && /CREATED|idp-created/.test(last.body)) return "created";
      if (last.status >= 400 || last.status === 303 || /NEED_PAYMENT/.test(last.body)) return "failed";
    }
    const state = await page.evaluate(() => {
      const text = document.body?.innerText ?? "";
      return {
        failed: /\bfailed\b/i.test(text) && /Provision Tide keys|Generating keys|setup/i.test(text),
        link: /Link your Tide account|Open the link to enroll/i.test(text),
      };
    }).catch(() => ({ failed: false, link: false }));
    if (state.link) return "reached-link";
    if (state.failed && w.calls.length > 0) return "failed";
    await page.waitForTimeout(500);
  }
  return "timeout";
}

async function fillAndSubmit(page: Page, appName: string, email: string, navTimeoutMs: number): Promise<void> {
  await page.locator('input[name="appName"]').waitFor({ state: "visible", timeout: navTimeoutMs });
  await page.locator('input[name="appName"]').fill(appName);
  const emailField = page.locator('input[name="email"]');
  await emailField.fill(""); // clear the session prefill
  await emailField.fill(email);
  // Terms checkbox: the submit button is disabled until it is ticked.
  const terms = page.locator('input[name="termsAccepted"], input[type="checkbox"]').last();
  if (!(await terms.isChecked().catch(() => false))) await terms.check().catch(() => terms.click());
  await page.locator('button[type="submit"]').first().click();
}

export function makeConsoleSetupOp(d: ConsoleSetupDeps): (ctx: OpContext) => Promise<OpOutcome> {
  let n = 0;
  const navTimeoutMs = 60_000;
  const setupTimeoutMs = 180_000;
  const base = `${d.tcBase.replace(/\/+$/, "")}/realms/master/tide-console/tide/setup`;
  return async () => {
    const seq = ++n;
    // The console slugifies the project name to the realm name, so name the project the realm.
    const { realm, email } = setupNames({ runId: d.runId, emailDomain: d.emailDomain, realmPrefix: "lt-ws" }, seq);
    d.manifest.upsertRealm({ realm, email, status: "created", purpose: "s3-setup", createdAt: new Date().toISOString() });
    const phases: Record<string, number> = {};
    const trail: string[] = [];
    const gc = await d.host.context();
    const page = await gc.context.newPage();
    page.setDefaultTimeout(navTimeoutMs);
    const w = watchSetup(page);
    let mark = Date.now();
    const lap = (k: string) => { const t = Date.now(); phases[k] = t - mark; mark = t; };
    try {
      await page.goto(base, { waitUntil: "domcontentloaded", timeout: navTimeoutMs });
      await loginIfNeeded(page, d.creds, d.tcBase, navTimeoutMs);
      lap("console_load");
      // The wizard may be served under the same path after login; make sure the form is there.
      if (!(await page.locator('input[name="appName"]').count())) {
        await page.goto(base, { waitUntil: "domcontentloaded", timeout: navTimeoutMs });
      }
      lap("admin_login");

      let outcome: "created" | "failed" | "reached-link" | "timeout" = "timeout";
      for (let attempt = 0; attempt <= d.retries; attempt++) {
        if (attempt === 0) {
          await fillAndSubmit(page, realm, email, navTimeoutMs);
          lap("wizard_submit");
        } else {
          // Mimic the user clicking Retry on failure.
          const retry = page.getByRole("button", { name: /retry/i }).first();
          if (!(await retry.count())) break;
          w.calls.length = 0;
          await retry.click();
        }
        outcome = await waitForSetupOutcome(page, w, setupTimeoutMs);
        const last = w.calls[w.calls.length - 1];
        trail.push(outcome === "created" ? "CREATED" : outcome === "reached-link" ? "CREATED(reached-link)" : last ? errorCode(last.body, last.status) : outcome);
        if (outcome === "created" || outcome === "reached-link") break;
      }
      lap("setup_done");

      const ok = outcome === "created" || outcome === "reached-link";
      const extra: Record<string, unknown> = { realm, attempts: trail.length, trail, reachedLink: outcome === "reached-link" };
      d.manifest.upsertRealm({ realm, email, purpose: "s3-setup", createdAt: new Date().toISOString(), status: ok ? "setup-ok" : "setup-failed", error: ok ? undefined : trail.join(" > ") });
      if (ok) return { ok: true, phases, extra };

      const last = w.calls[w.calls.length - 1];
      const text = `${last ? `setUpTideRealm HTTP ${last.status}: ${last.body}` : `wizard outcome ${outcome}`} | ${w.vendorErrors.join(" | ")}`;
      let code = last ? errorCode(last.body, last.status) : outcome === "timeout" ? "SETUP_TIMEOUT" : "SETUP_FAILED";
      if (trail.length > 1) code = `${code}_AFTER_RETRY`;
      return { ok: false, code, status: last?.status, message: text, phases, extra };
    } catch (e) {
      d.manifest.upsertRealm({ realm, email, purpose: "s3-setup", createdAt: new Date().toISOString(), status: "setup-failed", error: (e as Error).message });
      return { ok: false, code: "CONSOLE_DRIVER", message: `${(e as Error).message} | ${w.vendorErrors.join(" | ")}`, phases, extra: { realm } };
    } finally {
      await page.close().catch(() => undefined);
      await gc.close();
    }
  };
}

