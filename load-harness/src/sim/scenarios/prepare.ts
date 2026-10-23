// prepare-realms: build a pool of ready realms for S1/S2. Each realm goes through the S3 setup path,
// then gets self-registration, no forced email verification, and the harness OIDC client. A realm is
// listed only after its licence reads active and the Tide sign-up screen actually renders.

import type { AdminClient } from "../admin.js";
import type { ManifestWriter } from "../sink.js";
import { atomicWriteJson } from "../sink.js";
import { setupOnce, setupNames } from "./setup.js";
import { authorizeUrl, makePkce } from "../oidc.js";
import type { BrowserHost } from "./browser.js";
import { SIGNUP_SELECTORS } from "../../admin/signupFlow.js";
import { Pool } from "../pool.js";

export interface RealmsFile {
  runId: string;
  createdAt: string;
  target: string;
  seatsPerRealm: number;
  realms: Array<{ realm: string; ready: boolean; licence?: string; reason?: string }>;
}

export interface PrepareOpts {
  admin: AdminClient;
  manifest: ManifestWriter;
  host: BrowserHost | null;  // null skips the sign-up screen check
  runId: string;
  target: string;
  tcBase: string;
  count: number;
  concurrency: number;
  seatsPerRealm: number;
  emailDomain: string;
  retries: number;
  retryDelayMs: number;
  outPath: string;
  log: (s: string) => void;
}

async function signupScreenRenders(host: BrowserHost, tcBase: string, realm: string): Promise<string | null> {
  const gc = await host.context();
  const page = await gc.context.newPage();
  try {
    await page.goto(authorizeUrl(tcBase, realm, makePkce()), { waitUntil: "domcontentloaded", timeout: 60_000 });
    await page.locator(SIGNUP_SELECTORS.signInUsernameHost).first().waitFor({ state: "visible", timeout: 45_000 });
    const link = page.locator(SIGNUP_SELECTORS.createAccountLink).filter({ hasText: SIGNUP_SELECTORS.createAccountLinkText }).first();
    await link.waitFor({ state: "visible", timeout: 10_000 });
    return null;
  } catch (e) {
    return `sign-up screen check failed: ${(e as Error).message.split("\n")[0]}`;
  } finally {
    await page.close().catch(() => undefined);
    await gc.close();
  }
}

export async function prepareRealms(o: PrepareOpts): Promise<RealmsFile> {
  const file: RealmsFile = { runId: o.runId, createdAt: new Date().toISOString(), target: o.target, seatsPerRealm: o.seatsPerRealm, realms: [] };
  const pool = new Pool("prepare", o.concurrency);
  const save = () => atomicWriteJson(o.outPath, file);

  const one = async (n: number) => {
    const release = await pool.acquire();
    const { realm, email } = setupNames({ runId: o.runId, emailDomain: o.emailDomain, realmPrefix: "lt-pool" }, n);
    try {
      o.log(`[${realm}] setUpTideRealm`);
      const s = await setupOnce({ admin: o.admin, manifest: o.manifest, runId: o.runId, emailDomain: o.emailDomain, retries: o.retries, retryDelayMs: o.retryDelayMs, realmPrefix: "lt-pool", purpose: "pool" }, n);
      if (!s.ok) {
        file.realms.push({ realm, ready: false, reason: `setup failed: ${s.code}` });
        o.log(`[${realm}] setup failed ${s.code} ${s.message ?? ""}`.slice(0, 400));
        return;
      }
      const reg = await o.admin.openRegistration(realm);
      if (reg.status === 202) o.log(`[${realm}] realm update became a change request (IGA on?); registration may not be open`);
      else if (reg.status >= 300) throw new Error(`open registration HTTP ${reg.status}`);
      const signed = await o.admin.signIdpSettings(realm);
      if (signed.status !== 200) throw new Error(`sign-idp-settings HTTP ${signed.status}: ${signed.text.slice(0, 200)}`);
      const cl = await o.admin.ensureHarnessClient(realm);
      if (cl.status === 202) o.log(`[${realm}] client create became a change request (IGA on?)`);
      else if (cl.status >= 300) throw new Error(`create client HTTP ${cl.status}: ${cl.text.slice(0, 200)}`);

      const lic = await o.admin.subscriptionStatus(realm);
      // Midgard reports Stripe "active" as "upcoming renewal".
      const licence = lic.text.trim().replace(/^"|"$/g, "").toLowerCase();
      const reasons: string[] = [];
      if (lic.status !== 200 || !/^(active|trialing|upcoming renewal)$/.test(licence)) reasons.push(`licence not active (HTTP ${lic.status} "${licence.slice(0, 40)}")`);
      const cur = JSON.parse((await o.admin.getRealm(realm)).text) as { registrationAllowed?: boolean; verifyEmail?: boolean };
      if (!cur.registrationAllowed) reasons.push("registration not enabled");
      if (cur.verifyEmail) reasons.push("verifyEmail still on");
      if (o.host && !reasons.length) {
        const r = await signupScreenRenders(o.host, o.tcBase, realm);
        if (r) reasons.push(r);
      }
      const ready = reasons.length === 0;
      file.realms.push({ realm, ready, licence, reason: ready ? undefined : reasons.join("; ") });
      o.manifest.upsertRealm({ realm, email, purpose: "pool", createdAt: new Date().toISOString(), status: ready ? "ready" : "not-ready", licence, error: ready ? undefined : reasons.join("; ") });
      o.log(`[${realm}] ${ready ? "READY" : "NOT READY: " + reasons.join("; ")}`);
    } catch (e) {
      file.realms.push({ realm, ready: false, reason: (e as Error).message });
      o.manifest.upsertRealm({ realm, email, purpose: "pool", createdAt: new Date().toISOString(), status: "not-ready", error: (e as Error).message });
      o.log(`[${realm}] NOT READY: ${(e as Error).message}`);
    } finally {
      save();
      release();
    }
  };

  await Promise.all(Array.from({ length: o.count }, (_, i) => one(i + 1)));
  save();
  return file;
}
