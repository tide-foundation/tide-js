// prepare-realms: build a pool of ready realms for S1/S2.
//
// --tide-full (default) brings each realm to the same state as a customer realm after the console
// setup wizard's keygen block, so Tide users get EdDSA tokens minted through the ORKs (PreSign):
//   create realm -> registration on, verifyEmail off -> setUpTideRealm (free tier) -> licence check
//   -> iga.attestor=tide -> link-tide-account-action -> harness client -> sign IdP settings
//   -> toggle-iga (EdDSA + ADOPT scan + firstAdmin sign-defaults) -> approve every pending ADOPT CR
//   -> sign IdP settings -> verify: sign-up screen, probe sign-up + login, both tokens EdDSA.
// The realm stays in firstAdmin mode (no tide-realm-admin is granted), so every approval is a plain
// admin call and nothing needs the enclave.
//
// --basic keeps the IGA-off realm (RS256 tokens): setup, registration, client, licence + screen check.

import type { AdminClient, HttpResult } from "../admin.js";
import type { ManifestWriter, UsersSecret } from "../sink.js";
import { atomicWriteJson } from "../sink.js";
import { setupOnce, setupNames } from "./setup.js";
import { authorizeUrl, makePkce } from "../oidc.js";
import { RealmPool, LoginUserPool, makeSignupOp, makeLoginOp, newRunPassword, type BrowserHost } from "./browser.js";
import { SIGNUP_SELECTORS } from "../../admin/signupFlow.js";
import { Pool } from "../pool.js";
import type { OpContext } from "../engine.js";

export interface RealmsFileEntry {
  realm: string;
  ready: boolean;
  tideFull: boolean;
  seats: number;            // sign-ups left for load runs (the probe user already took one)
  licence?: string;
  reason?: string;
  timings?: Record<string, number>;
  probe?: { signupAlg?: string; loginAlg?: string };
}

export interface RealmsFile {
  runId: string;
  createdAt: string;
  target: string;
  seatsPerRealm: number;
  mode: "tide-full" | "basic";
  realms: RealmsFileEntry[];
}

export interface PrepareOpts {
  admin: AdminClient;
  manifest: ManifestWriter;
  secret: UsersSecret;
  host: BrowserHost | null;  // null skips the browser checks (basic mode only)
  runId: string;
  target: string;
  tcBase: string;
  count: number;
  concurrency: number;
  seatsPerRealm: number;
  emailDomain: string;
  retries: number;
  retryDelayMs: number;
  tideFull: boolean;
  outPath: string;
  log: (s: string) => void;
}

const CTX: OpContext = { seq: 0, step: 0, stop: () => undefined, aborted: () => false };

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

function must(r: HttpResult, what: string, ok: number[] = [200, 201, 204]): void {
  if (r.status === 202) throw new Error(`${what} became a change request (IGA already on?)`);
  if (!ok.includes(r.status)) throw new Error(`${what} HTTP ${r.status}: ${r.text.slice(0, 200)}`);
}

// Approve every pending CR until a full pass finds none (dependent ADOPTs surface late).
async function drainPending(admin: AdminClient, realm: string, log: (s: string) => void): Promise<{ approved: number; left: number }> {
  let approved = 0;
  for (let pass = 0; pass < 12; pass++) {
    const pending = await admin.pendingChangeRequests(realm);
    if (!pending.length) return { approved, left: 0 };
    for (const cr of pending) {
      const r = await admin.approveChangeRequest(realm, cr.id);
      if (r.status === 200) {
        const j = JSON.parse(r.text || "{}") as { mode?: string; committed?: boolean };
        if (j.mode !== "recorded") throw new Error(`CR ${cr.actionType ?? cr.id} wants an enclave approval (mode ${j.mode}); realm is not in firstAdmin mode`);
        approved++;
      } else if (![404, 409, 412].includes(r.status)) {
        throw new Error(`approve ${cr.actionType ?? cr.id} HTTP ${r.status}: ${r.text.slice(0, 200)}`);
      }
    }
    log(`[${realm}] drain pass ${pass + 1}: ${pending.length} pending`);
  }
  return { approved, left: (await admin.pendingChangeRequests(realm)).length };
}

// Probe: one real sign-up and one login through the enclave; both tokens must be EdDSA.
async function probeTideSigned(o: PrepareOpts, realm: string, n: number): Promise<{ reason: string | null; signupAlg?: string; loginAlg?: string }> {
  const password = newRunPassword();
  const pool = new RealmPool([{ realm, seats: 1, tideFull: true }]);
  const logins = new LoginUserPool();
  const signup = makeSignupOp({
    host: o.host!, tcBase: o.tcBase, runId: `${o.runId}-probe${n}`, emailDomain: o.emailDomain, password,
    realms: pool, manifest: o.manifest, secret: o.secret, loginPool: logins, exchangeToken: true, log: o.log,
  });
  const s = await signup(CTX);
  const signupAlg = s.extra?.alg as string | undefined;
  if (!s.ok) return { reason: `probe sign-up failed: ${s.code} ${(s.message ?? "").slice(0, 200)}`, signupAlg };
  const login = makeLoginOp({ host: o.host!, tcBase: o.tcBase, users: logins, navTimeoutMs: 60_000 });
  const l = await login(CTX);
  const loginAlg = l.extra?.alg as string | undefined;
  if (!l.ok) return { reason: `probe login failed: ${l.code} ${(l.message ?? "").slice(0, 200)}`, signupAlg, loginAlg };
  return { reason: null, signupAlg, loginAlg };
}

export async function prepareRealms(o: PrepareOpts): Promise<RealmsFile> {
  const file: RealmsFile = { runId: o.runId, createdAt: new Date().toISOString(), target: o.target, seatsPerRealm: o.seatsPerRealm, mode: o.tideFull ? "tide-full" : "basic", realms: [] };
  const pool = new Pool("prepare", o.concurrency);
  const save = () => atomicWriteJson(o.outPath, file);

  const one = async (n: number) => {
    const release = await pool.acquire();
    const { realm, email } = setupNames({ runId: o.runId, emailDomain: o.emailDomain, realmPrefix: "lt-pool" }, n);
    const timings: Record<string, number> = {};
    const timed = async <T>(name: string, f: () => Promise<T>): Promise<T> => {
      const t0 = Date.now();
      try { return await f(); } finally { timings[name] = Date.now() - t0; }
    };
    const entry: RealmsFileEntry = { realm, ready: false, tideFull: o.tideFull, seats: 0, timings };
    try {
      o.log(`[${realm}] create + setUpTideRealm (${o.tideFull ? "tide-full" : "basic"})`);
      const s = await timed("setup", () => setupOnce({
        admin: o.admin, manifest: o.manifest, runId: o.runId, emailDomain: o.emailDomain, retries: o.retries,
        retryDelayMs: o.retryDelayMs, realmPrefix: "lt-pool", purpose: "pool",
        beforeSetup: async (r) => must(await o.admin.openRegistration(r), "open registration"),
      }, n));
      if (!s.ok) throw new Error(`setup failed: ${s.code} ${(s.message ?? "").slice(0, 200)}`);

      const lic = await timed("licence", () => o.admin.subscriptionStatus(realm));
      // Midgard reports Stripe "active" as "upcoming renewal".
      const licence = lic.text.trim().replace(/^"|"$/g, "").toLowerCase();
      entry.licence = licence;
      if (lic.status !== 200 || !/^(active|trialing|upcoming renewal)$/.test(licence)) throw new Error(`licence not active (HTTP ${lic.status} "${licence.slice(0, 40)}")`);

      if (o.tideFull) {
        await timed("attestor", async () => must(await o.admin.setRealmAttributes(realm, { "iga.attestor": "tide" }), "set iga.attestor"));
        await timed("link_action", async () => must(await o.admin.ensureLinkTideAction(realm), "register link-tide-account-action"));
      }
      await timed("client", async () => must(await o.admin.ensureHarnessClient(realm), "create harness client"));
      await timed("sign_idp", async () => must(await o.admin.signIdpSettings(realm), "sign-idp-settings", [200]));

      if (o.tideFull) {
        const before = JSON.parse((await o.admin.getRealm(realm)).text) as { attributes?: Record<string, string> };
        if (before.attributes?.isIGAEnabled !== "true") {
          const t = await timed("toggle_iga", () => o.admin.toggleIga(realm));
          must(t, "toggle-iga", [200]);
          const tj = JSON.parse(t.text || "{}") as { warnings?: unknown };
          if (tj.warnings) o.log(`[${realm}] toggle-iga warnings: ${JSON.stringify(tj.warnings).slice(0, 300)}`);
        }
        const d = await timed("drain_crs", () => drainPending(o.admin, realm, o.log));
        o.log(`[${realm}] approved ${d.approved} pending CR(s), ${d.left} left`);
        if (d.left > 0) throw new Error(`${d.left} change request(s) still pending after drain`);
        await timed("sign_idp_2", async () => must(await o.admin.signIdpSettings(realm), "sign-idp-settings after IGA", [200]));
      }

      // State checks.
      const cur = JSON.parse((await o.admin.getRealm(realm)).text) as { registrationAllowed?: boolean; verifyEmail?: boolean; defaultSignatureAlgorithm?: string; attributes?: Record<string, string> };
      const reasons: string[] = [];
      if (!cur.registrationAllowed) reasons.push("registration not enabled");
      if (cur.verifyEmail) reasons.push("verifyEmail still on");
      if (o.tideFull) {
        if (cur.attributes?.isIGAEnabled !== "true") reasons.push("IGA not enabled");
        if (cur.attributes?.["iga.attestor"] !== "tide") reasons.push(`iga.attestor=${cur.attributes?.["iga.attestor"] ?? "unset"}`);
        if (cur.defaultSignatureAlgorithm !== "EdDSA") reasons.push(`defaultSignatureAlgorithm=${cur.defaultSignatureAlgorithm}`);
      }
      if (!reasons.length && o.host) {
        const r = await timed("screen_check", () => signupScreenRenders(o.host!, o.tcBase, realm));
        if (r) reasons.push(r);
      }
      let seats = o.seatsPerRealm;
      if (!reasons.length && o.tideFull) {
        if (!o.host) reasons.push("tide-full verification needs the browser (drop --no-browser-check)");
        else {
          const p = await timed("probe", () => probeTideSigned(o, realm, n));
          entry.probe = { signupAlg: p.signupAlg, loginAlg: p.loginAlg };
          if (p.signupAlg) seats -= 1;
          if (p.reason) reasons.push(p.reason);
        }
      }
      entry.ready = reasons.length === 0;
      entry.seats = Math.max(0, seats);
      entry.reason = entry.ready ? undefined : reasons.join("; ");
      o.manifest.upsertRealm({ realm, email, purpose: "pool", createdAt: new Date().toISOString(), status: entry.ready ? "ready" : "not-ready", licence, error: entry.reason });
      o.log(`[${realm}] ${entry.ready ? "READY" : "NOT READY: " + entry.reason} timings=${JSON.stringify(timings)}${entry.probe ? " probe=" + JSON.stringify(entry.probe) : ""}`);
    } catch (e) {
      entry.reason = (e as Error).message;
      o.manifest.upsertRealm({ realm, email, purpose: "pool", createdAt: new Date().toISOString(), status: "not-ready", error: entry.reason });
      o.log(`[${realm}] NOT READY: ${entry.reason} timings=${JSON.stringify(timings)}`);
    } finally {
      file.realms.push(entry);
      save();
      release();
    }
  };

  await Promise.all(Array.from({ length: o.count }, (_, i) => one(i + 1)));
  save();
  return file;
}
