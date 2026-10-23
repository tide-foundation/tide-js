// S1 sign-up and S2 login through the real enclave in Playwright, plus the Node-only refresh op.
// One fresh context per operation on a local Chromium or remote Azure browsers, concurrency capped
// by the shared browser pool.

import { chromium, type Browser, type Page } from "playwright";
import { randomBytes } from "node:crypto";
import { driveSignUpFlow } from "../../admin/signupFlow.js";
import { sweFormFill, sweClickSignIn } from "../../warmup/oidc.js";
import { authorizeUrl, exchangeCode, guardedContext, makePkce, refreshGrant } from "../oidc.js";
import { CALLBACK_URL, type TargetName } from "../targets.js";
import type { OpContext, OpOutcome } from "../engine.js";
import type { ManifestWriter, UsersSecret } from "../sink.js";
import { matchSignatures } from "../signatures.js";
import { connectAzureBrowsers, usageOf, type BrowserEndpoint, type BrowserUsage, type Session } from "../remote.js";

// ---------------------------------------------------------------------------
// Browser host
// ---------------------------------------------------------------------------

export interface BrowserHostOpts {
  headless: boolean;
  target: TargetName;
  onProdHit: (host: string) => void;
  log: (s: string) => void;
  endpoint?: BrowserEndpoint;      // default local
  remoteBrowsers?: number;         // azure only
  contextsPerBrowser?: number;     // azure only, for the usage record
}

// One local Chromium, or N remote browsers in an Azure Playwright workspace. Each operation gets a
// fresh context on the least-busy browser.
export class BrowserHost {
  private browsers: Browser[] = [];
  private active = new Map<Browser, number>();
  private sessions: Session[] = [];
  private stopped = false;
  readonly endpoint: BrowserEndpoint;

  constructor(private o: BrowserHostOpts) {
    this.endpoint = o.endpoint ?? "local";
  }

  async start(): Promise<void> {
    if (this.endpoint === "local") {
      this.browsers = [await chromium.launch({ headless: this.o.headless })];
    } else {
      const r = await connectAzureBrowsers(this.o.remoteBrowsers ?? 1, this.o.log);
      this.browsers = r.browsers;
      this.sessions = r.sessions;
      if (!this.browsers.length) throw new Error("no remote browser could be connected (see the log for the reason)");
    }
    for (const b of this.browsers) this.active.set(b, 0);
  }

  // Closes every browser; safe to call more than once. Remote sessions stop billing here.
  async stop(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    await Promise.all(this.browsers.map(async (b, i) => {
      await b.close().catch(() => undefined);
      const s = this.sessions[i];
      if (s && s.closedAt === null && s.openedAt !== null) s.closedAt = Date.now();
    }));
  }

  usage(): BrowserUsage {
    return usageOf(this.endpoint, this.sessions, this.endpoint === "azure" ? this.o.contextsPerBrowser ?? null : null);
  }

  async context() {
    const alive = this.browsers.filter((b) => b.isConnected());
    if (!alive.length) throw new Error(this.stopped ? "browser host stopped" : "no connected browser");
    const b = alive.reduce((x, y) => ((this.active.get(y) ?? 0) < (this.active.get(x) ?? 0) ? y : x));
    this.active.set(b, (this.active.get(b) ?? 0) + 1);
    let gc;
    try {
      gc = await guardedContext(b, this.o.target, (host, denied) => {
        if (denied) this.o.onProdHit(host);
        else this.o.log(`note: browser reached off-allowlist host ${host} (allowed, reported once)`);
      });
    } catch (e) {
      this.active.set(b, (this.active.get(b) ?? 1) - 1);
      throw e;
    }
    const close = gc.close;
    let done = false;
    return { ...gc, close: async () => { await close(); if (!done) { done = true; this.active.set(b, (this.active.get(b) ?? 1) - 1); } } };
  }
}

// Collect ORK and TideCloak error bodies seen by the page so failure signatures are visible
// even when the enclave only shows a spinner.
function watchErrors(page: Page, onBody?: (body: string) => void): string[] {
  const seen: string[] = [];
  page.on("response", async (res) => {
    if (res.status() < 400 || seen.length >= 4) return;
    const url = res.url();
    if (!/\/Authentication\/|\/realms\/|\/tidevouchers\//.test(url)) return;
    try {
      const body = (await res.text()).slice(0, 300);
      seen.push(`HTTP ${res.status()} ${new URL(url).pathname}: ${body}`);
      onBody?.(body);
    } catch { /* body gone */ }
  });
  return seen;
}

async function pageText(page: Page): Promise<string> {
  try {
    return (await page.evaluate(() => document.body?.innerText ?? "")).replace(/\s+/g, " ").slice(0, 300);
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Realm pool (S1 seat spreading)
// ---------------------------------------------------------------------------

export interface PoolRealm { realm: string; seats: number; tideFull?: boolean }

export class RealmPool {
  private seats: Map<string, number>;
  private full: Set<string>;
  private order: string[];
  private i = 0;
  constructor(realms: PoolRealm[]) {
    this.order = realms.map((r) => r.realm);
    this.seats = new Map(realms.map((r) => [r.realm, r.seats]));
    this.full = new Set(realms.filter((r) => r.tideFull).map((r) => r.realm));
  }
  // Round-robin over realms that still have seats; null when none do.
  take(): string | null {
    for (let k = 0; k < this.order.length; k++) {
      const r = this.order[(this.i + k) % this.order.length];
      if ((this.seats.get(r) ?? 0) > 0) {
        this.i = (this.i + k + 1) % this.order.length;
        this.seats.set(r, (this.seats.get(r) ?? 0) - 1);
        return r;
      }
    }
    return null;
  }
  // Give a seat back when a sign-up failed for a reason other than the cap.
  giveBack(realm: string): void {
    this.seats.set(realm, (this.seats.get(realm) ?? 0) + 1);
  }
  markFull(realm: string): void {
    this.seats.set(realm, 0);
  }
  // Realms prepared with --tide-full must mint EdDSA (Tide-signed) tokens.
  isTideFull(realm: string): boolean {
    return this.full.has(realm);
  }
  remaining(): number {
    let n = 0;
    for (const v of this.seats.values()) n += v;
    return n;
  }
  size(): number { return this.order.length; }
}

const NOT_TIDE_SIGNED = (alg: string | undefined) =>
  `token alg ${alg ?? "unknown"} on a realm that should be Tide-signed (EdDSA): mint did not go through the Tide network`;

// ---------------------------------------------------------------------------
// Login user pool (S2), spread across users to stay under the per-user throttle
// ---------------------------------------------------------------------------

export interface PoolUser { userId: string; realm: string; password: string; tideFull?: boolean }

export class LoginUserPool {
  private users: PoolUser[] = [];
  private i = 0;
  add(u: PoolUser): void { this.users.push(u); }
  size(): number { return this.users.length; }
  next(): PoolUser | null {
    if (!this.users.length) return null;
    const u = this.users[this.i % this.users.length];
    this.i++;
    return u;
  }
  passwords(): string[] { return [...new Set(this.users.map((u) => u.password))]; }
}

// Refresh tokens kept in memory only, for the refresh op.
export class RefreshStore {
  private items: Array<{ realm: string; token: string; mustSign: boolean }> = [];
  private i = 0;
  constructor(private max = 500) {}
  put(realm: string, token: string, mustSign = false): void {
    this.items.push({ realm, token, mustSign });
    if (this.items.length > this.max) this.items.shift();
  }
  take(): { realm: string; token: string; mustSign: boolean } | null {
    if (!this.items.length) return null;
    const it = this.items[this.i % this.items.length];
    this.i++;
    return it;
  }
  replace(old: string, realm: string, token: string): void {
    const k = this.items.findIndex((x) => x.token === old);
    if (k >= 0) this.items[k] = { ...this.items[k], realm, token };
  }
  size(): number { return this.items.length; }
}

// ---------------------------------------------------------------------------
// S1 sign-up op
// ---------------------------------------------------------------------------

export interface SignupDeps {
  host: BrowserHost;
  tcBase: string;
  runId: string;
  emailDomain: string;
  password: string;
  realms: RealmPool;
  manifest: ManifestWriter;
  secret: UsersSecret;
  loginPool?: LoginUserPool;   // incident mode: new users join the login pool
  exchangeToken: boolean;
  log: (s: string) => void;
}

export function makeSignupOp(d: SignupDeps): (ctx: OpContext) => Promise<OpOutcome> {
  let n = 0;
  return async (ctx) => {
    const realm = d.realms.take();
    if (!realm) {
      ctx.stop(`realm pool exhausted (${d.realms.size()} realms, all seats used): need more realms. Run prepare-realms and pass --realms-from. This is a pool limit, not a staging failure.`);
      return { ok: false, code: "REALM_POOL_EXHAUSTED", expected: true };
    }
    const userId = `lt-${d.runId}-${++n}`;
    const email = `${userId}@${d.emailDomain}`;
    d.manifest.upsertUser({ userId, realm, email, status: "attempted", at: new Date().toISOString() });

    const pkce = makePkce();
    const gc = await d.host.context();
    const page = await gc.context.newPage();
    // The enclave just spins on a seat-cap refusal, so close the page to fail fast.
    const errs = watchErrors(page, (body) => {
      if (matchSignatures(body).some((s) => s.id === "SEAT_CAP")) void page.close().catch(() => undefined);
    });
    try {
      const res = await driveSignUpFlow({
        context: gc.context,
        page,
        authUrl: authorizeUrl(d.tcBase, realm, pkce),
        callbackOrigin: new URL(CALLBACK_URL).origin,
        user: { userId, password: d.password },
        email,
      });
      const phases = { ...res.phases };
      const extra: Record<string, unknown> = { realm, userId, lastStep: res.step, emailStep: res.emailStepShown, vouchers: res.voucherDraws };
      if (!res.ok) {
        const text = `${res.errorMessage ?? ""} | ${errs.join(" | ")} | page: ${await pageText(page)}`;
        const capped = matchSignatures(text).some((s) => s.id === "SEAT_CAP");
        if (capped) {
          d.realms.markFull(realm);
          d.manifest.upsertUser({ userId, realm, email, status: "seat-cap", at: new Date().toISOString() });
          return { ok: false, code: "SEAT_CAP", message: text, phases, extra, expected: true };
        }
        d.realms.giveBack(realm);
        d.manifest.upsertUser({ userId, realm, email, status: "failed", at: new Date().toISOString() });
        return { ok: false, code: `SIGNUP_${res.step.toUpperCase().replace(/-/g, "_")}`, message: text, phases, extra };
      }
      const cb = new URL(res.callbackUrl!);
      if (cb.searchParams.get("error")) {
        d.manifest.upsertUser({ userId, realm, email, status: "failed", at: new Date().toISOString() });
        return { ok: false, code: "CALLBACK_ERROR", message: `${cb.searchParams.get("error")}: ${cb.searchParams.get("error_description") ?? ""}`, phases, extra };
      }
      const tideFull = d.realms.isTideFull(realm);
      d.secret.add({ userId, realm, password: d.password, tideFull });
      d.manifest.upsertUser({ userId, realm, email, status: "created", at: new Date().toISOString() });
      d.loginPool?.add({ userId, realm, password: d.password, tideFull });
      if (d.exchangeToken) {
        const tok = await exchangeCode(d.tcBase, realm, cb.searchParams.get("code") ?? "", pkce.verifier);
        phases.token_ms = tok.ms;
        if (!tok.ok) return { ok: false, code: "TOKEN_MINT_FAILED", status: tok.status, message: `account created, token mint failed: ${tok.error}`, phases, extra };
        extra.alg = tok.alg;
        if (tideFull && tok.alg !== "EdDSA") return { ok: false, code: "NOT_TIDE_SIGNED", message: NOT_TIDE_SIGNED(tok.alg), phases, extra };
      }
      return { ok: true, phases, extra };
    } finally {
      await page.close().catch(() => undefined);
      await gc.close();
    }
  };
}

// ---------------------------------------------------------------------------
// S2 login op
// ---------------------------------------------------------------------------

export interface LoginDeps {
  host: BrowserHost;
  tcBase: string;
  users: LoginUserPool;
  refresh?: RefreshStore;
  navTimeoutMs: number;
  expectEddsa?: boolean;   // treat every login as Tide-signed, not just tideFull users
}

export function makeLoginOp(d: LoginDeps): (ctx: OpContext) => Promise<OpOutcome> {
  return async () => {
    const user = d.users.next();
    if (!user) return { ok: false, code: "NO_LOGIN_USERS", expected: true, message: "login pool empty (no users yet)" };
    const pkce = makePkce();
    const gc = await d.host.context();
    const page = await gc.context.newPage();
    page.setDefaultTimeout(d.navTimeoutMs);
    const errs = watchErrors(page);
    const phases: Record<string, number> = {};
    let mark = Date.now();
    const lap = (k: string) => { const t = Date.now(); phases[k] = t - mark; mark = t; };
    const extra: Record<string, unknown> = { realm: user.realm, userId: user.userId };
    let stage = "authorize";
    try {
      await page.goto(authorizeUrl(d.tcBase, user.realm, pkce), { waitUntil: "domcontentloaded" });
      stage = "enclave";
      const pw = await sweFormFill(page, { userId: user.userId, password: user.password }, d.navTimeoutMs);
      lap("enclave_load");
      stage = "sign_in";
      await sweClickSignIn(page, pw, d.navTimeoutMs);
      const cb = await Promise.race([
        gc.callback,
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error("callback not reached in time")), d.navTimeoutMs * 2)),
      ]);
      lap("sign_in_to_callback");
      if (cb.searchParams.get("error")) {
        return { ok: false, code: "CALLBACK_ERROR", message: `${cb.searchParams.get("error")}: ${cb.searchParams.get("error_description") ?? ""}`, phases, extra };
      }
      stage = "token";
      const tok = await exchangeCode(d.tcBase, user.realm, cb.searchParams.get("code") ?? "", pkce.verifier);
      phases.token_ms = tok.ms;
      if (!tok.ok) return { ok: false, code: "TOKEN_MINT_FAILED", status: tok.status, message: tok.error, phases, extra };
      extra.alg = tok.alg;
      const mustSign = !!user.tideFull || !!d.expectEddsa;
      if (d.refresh && tok.refreshToken) d.refresh.put(user.realm, tok.refreshToken, mustSign);
      if (mustSign && tok.alg !== "EdDSA") return { ok: false, code: "NOT_TIDE_SIGNED", message: NOT_TIDE_SIGNED(tok.alg), phases, extra };
      return { ok: true, phases, extra };
    } catch (e) {
      const text = `${(e as Error).message} | ${errs.join(" | ")} | page: ${await pageText(page)}`;
      return { ok: false, code: `LOGIN_${stage.toUpperCase()}`, message: text, phases, extra };
    } finally {
      await page.close().catch(() => undefined);
      await gc.close();
    }
  };
}

// Refresh grant: each one re-mints and re-signs the token server side, no browser needed.
export function makeRefreshOp(tcBase: string, store: RefreshStore): (ctx: OpContext) => Promise<OpOutcome> {
  return async () => {
    const it = store.take();
    if (!it) return { ok: false, code: "NO_REFRESH_TOKENS", expected: true, message: "no refresh tokens yet (needs successful logins first)" };
    const r = await refreshGrant(tcBase, it.realm, it.token);
    if (r.ok && r.refreshToken) store.replace(it.token, it.realm, r.refreshToken);
    if (r.ok && it.mustSign && r.alg !== "EdDSA") return { ok: false, code: "NOT_TIDE_SIGNED", message: NOT_TIDE_SIGNED(r.alg), phases: { token_ms: r.ms } };
    return r.ok ? { ok: true, phases: { token_ms: r.ms }, extra: { realm: it.realm, alg: r.alg } } : { ok: false, code: "REFRESH_FAILED", status: r.status, message: r.error, phases: { token_ms: r.ms } };
  };
}

export function newRunPassword(): string {
  return randomBytes(15).toString("base64").replace(/[+/=]/g, "x") + "aA1!";
}
