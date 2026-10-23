// OIDC helpers: PKCE, authorize URL, guarded browser contexts that catch the callback, code exchange.

import { createHash, randomBytes } from "node:crypto";
import type { Browser, BrowserContext } from "playwright";
import { CALLBACK_URL, OIDC_CLIENT_ID, isDeniedHost, type TargetName, isAllowedHost } from "./targets.js";

export interface Pkce { verifier: string; challenge: string; state: string }

function b64url(b: Buffer): string {
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function makePkce(): Pkce {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()), state: b64url(randomBytes(16)) };
}

export function authorizeUrl(tcBase: string, realm: string, pkce: Pkce, clientId = OIDC_CLIENT_ID): string {
  const u = new URL(`${tcBase}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/auth`);
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", CALLBACK_URL);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("scope", "openid");
  u.searchParams.set("state", pkce.state);
  u.searchParams.set("code_challenge", pkce.challenge);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("kc_idp_hint", "tide");
  return u.toString();
}

export interface GuardedContext {
  context: BrowserContext;
  callback: Promise<URL>;
  close: () => Promise<void>;
}

// A fresh context per operation (clean cookies). Requests to production hosts are blocked and abort
// the run. Other hosts outside the allowlist are let through but reported once, so an unexpected
// dependency shows up in the log instead of silently breaking the flow. The code is read from the
// callback request itself, so no local server is needed (whatever listens on port 3000 just sees
// a request it can ignore).
const reportedHosts = new Set<string>();

export async function guardedContext(
  browser: Browser,
  target: TargetName,
  onViolation: (host: string, denied: boolean) => void,
): Promise<GuardedContext> {
  const context = await browser.newContext();
  const cb = new URL(CALLBACK_URL);
  let resolveCb!: (u: URL) => void;
  const callback = new Promise<URL>((r) => { resolveCb = r; });

  await context.route((url) => isDeniedHost(url.hostname), async (route) => {
    onViolation(new URL(route.request().url()).hostname, true);
    await route.abort("blockedbyclient");
  });

  context.on("request", (req) => {
    let u: URL;
    try { u = new URL(req.url()); } catch { return; }
    if (!/^https?:$/.test(u.protocol)) return;
    // The callback arrives as a redirect, which route handlers never see, so catch it here.
    if (u.hostname === cb.hostname) { if (u.origin === cb.origin && u.pathname === cb.pathname) resolveCb(u); return; }
    if (isAllowedHost(target, u.hostname) || isDeniedHost(u.hostname) || reportedHosts.has(u.hostname)) return;
    reportedHosts.add(u.hostname);
    onViolation(u.hostname, false);
  });

  await context.route((url) => url.origin === cb.origin && url.pathname === cb.pathname, async (route) => {
    resolveCb(new URL(route.request().url()));
    await route.fulfill({ status: 200, contentType: "text/plain", body: "ok" });
  });

  return { context, callback, close: () => context.close().catch(() => undefined) };
}

export interface TokenResult {
  ok: boolean;
  status: number;
  ms: number;
  error?: string;
  hasDoken?: boolean;
  hasRefresh?: boolean;
  alg?: string;          // access token JWS alg; EdDSA means it was signed by the Tide network
  refreshToken?: string; // kept in memory only, for --refresh-loop
}

export async function exchangeCode(tcBase: string, realm: string, code: string, verifier: string, clientId = OIDC_CLIENT_ID): Promise<TokenResult> {
  const t0 = Date.now();
  const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CALLBACK_URL, client_id: clientId, code_verifier: verifier });
  return tokenCall(tcBase, realm, body, t0);
}

export async function refreshGrant(tcBase: string, realm: string, refreshToken: string, clientId = OIDC_CLIENT_ID): Promise<TokenResult> {
  const t0 = Date.now();
  const body = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId });
  return tokenCall(tcBase, realm, body, t0);
}

async function tokenCall(tcBase: string, realm: string, body: URLSearchParams, t0: number): Promise<TokenResult> {
  let res: Response;
  try {
    res = await fetch(`${tcBase}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
  } catch (e) {
    return { ok: false, status: 0, ms: Date.now() - t0, error: `token request failed: ${(e as Error).message}` };
  }
  const text = await res.text();
  const ms = Date.now() - t0;
  if (!res.ok) return { ok: false, status: res.status, ms, error: `token HTTP ${res.status}: ${text.slice(0, 400)}` };
  try {
    const j = JSON.parse(text) as { access_token?: string; refresh_token?: string; doken?: string };
    if (!j.access_token) return { ok: false, status: res.status, ms, error: "token response had no access_token" };
    let alg: string | undefined;
    try { alg = JSON.parse(Buffer.from(j.access_token.split(".")[0], "base64url").toString()).alg; } catch { /* opaque token */ }
    return { ok: true, status: res.status, ms, hasDoken: !!j.doken, hasRefresh: !!j.refresh_token, refreshToken: j.refresh_token, alg };
  } catch {
    return { ok: false, status: res.status, ms, error: "token response was not JSON" };
  }
}
