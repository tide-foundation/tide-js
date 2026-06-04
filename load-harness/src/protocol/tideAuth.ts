//
// TideCloak-side fetches for the browserless cmkOnly flow.
//
// Fetch 1: GET /realms/<realm>/protocol/openid-connect/auth?...&kc_idp_hint=tide
//   - With redirect-follow OFF (we step through each 303 by hand so the
//     cookie jar sees Set-Cookie at each hop and we can extract the
//     final SWE URL out of the third Location header).
//   - Captures KC_AUTH_SESSION_HASH (the only functionally-required
//     cookie) and the 11 SWE URL params.
//
// Fetch 2: GET <vRedirectUri>?state=<inner-state>&vendorEncryptedData=<...>
//   - Redirect-follow OFF (we want the 302 Location header, NOT the
//     follow target, which would be a different origin we don't need
//     to hit).
//   - Returns { code, state } parsed from the Location header.
//
// SECURITY:
//   * Origin / Referer NOT set — R2 preflight confirmed TideCloak does
//     not enforce either on this realm. Adding them would only add risk
//     of breakage if a future Keycloak version started checking.
//   * No password handling on this layer (the cmkOnly flow never sends
//     a password to TideCloak; the password egress is inside the ORK
//     Convert call in R4's crypto port).
//

import "./undici-setup.js";
import { fetch } from "undici";

import type { PerVUJar } from "./cookie-jar.js";
import { KNOWN_PARAMS, type SweUrlParams } from "./types.js";

// Hard cap on the number of redirects we'll chase during Fetch 1.
// R2 preflight observed exactly 2 redirects (/auth -> /broker/tide/login
// -> sork SWE URL). 5 gives headroom without becoming an open loop.
const MAX_REDIRECTS = 5;

export interface FetchAuthorizeOpts {
  tcBase:        string;          // e.g. "https://staging.dauth.me"
  tcRealm:       string;          // e.g. "tide-metrics-load"
  clientId:      string;
  callbackUrl:   string;          // the OIDC redirect_uri we registered with TideCloak
  state:         string;
  codeChallenge: string;
  kcIdpHint:     string;          // typically "tide"
  cookieJar:     PerVUJar;
}

/**
 * Drive Fetch 1: TideCloak `/auth` → SWE URL.
 *
 * Returns the parsed SWE URL params. Side-effect: the supplied
 * cookie jar will have `KC_AUTH_SESSION_HASH` set (plus any other
 * cookies TideCloak emits along the way).
 */
export async function fetchAuthorize(opts: FetchAuthorizeOpts): Promise<SweUrlParams> {
  const authUrl = buildAuthorizeUrl(opts);

  let nextUrl: string | null = authUrl;
  let lastResponseUrl: string | null = null;
  let sweUrl: string | null = null;

  for (let hop = 0; hop < MAX_REDIRECTS; hop++) {
    if (!nextUrl) break;
    const cookieHeader = await opts.cookieJar.cookieHeader(nextUrl);
    const headers: Record<string, string> = {
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    };
    if (cookieHeader) headers["cookie"] = cookieHeader;

    const res = await fetch(nextUrl, {
      method: "GET",
      headers,
      redirect: "manual",
    });

    // Ingest Set-Cookie from THIS hop's response, scoped to the URL we
    // just sent the request to. (undici's getSetCookie returns each
    // Set-Cookie line individually, which is what tough-cookie wants.)
    const setCookies = res.headers.getSetCookie();
    if (setCookies.length > 0) {
      await opts.cookieJar.ingestSetCookie(nextUrl, setCookies);
    }

    lastResponseUrl = nextUrl;

    // 30x with Location → continue.
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      // Drain the body to free the socket back to the pool.
      await res.body?.cancel().catch(() => undefined);
      if (!loc) {
        throw new Error(`Fetch 1: status ${res.status} with no Location header`);
      }
      // Resolve relative redirects against the URL we just hit.
      const resolved = new URL(loc, nextUrl).toString();
      // If the redirect target is on the SWE host (sork*) and carries
      // the SWE param block, that's our terminal URL.
      if (isSweUrl(resolved)) {
        sweUrl = resolved;
        break;
      }
      nextUrl = resolved;
      continue;
    }

    // Non-redirect: either the SWE URL came back as a 200 (unlikely)
    // or this realm/client config is broken.
    await res.body?.cancel().catch(() => undefined);
    if (res.status === 200 && isSweUrl(lastResponseUrl ?? "")) {
      sweUrl = lastResponseUrl!;
      break;
    }
    throw new Error(
      `Fetch 1: unexpected non-redirect status ${res.status} at ${redact(nextUrl)}`,
    );
  }

  if (!sweUrl) {
    throw new Error(
      `Fetch 1: did not land on a SWE URL within ${MAX_REDIRECTS} hops`,
    );
  }

  return parseSweUrl(sweUrl);
}

export interface FetchBrokerCallbackOpts {
  vRedirectUri:         string;
  state:                string;
  vendorEncryptedData:  string;
  cookieJar:            PerVUJar;
}

/**
 * Drive Fetch 2: the terminal GET to TideCloak that completes the
 * cmkOnly chain and triggers a 302 to the registered redirect_uri.
 *
 * Returns the OIDC `code` + `state` parsed from the 302 Location header.
 * Stops there — exchanging the code for a token is the existing
 * /callback flow in server.ts and is outside this module's scope.
 */
export async function fetchBrokerCallback(
  opts: FetchBrokerCallbackOpts,
): Promise<{ code: string; state: string }> {
  const url = new URL(opts.vRedirectUri);
  url.searchParams.set("state", opts.state);
  url.searchParams.set("vendorEncryptedData", opts.vendorEncryptedData);

  const target = url.toString();
  const cookieHeader = await opts.cookieJar.cookieHeader(target);
  const headers: Record<string, string> = {
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  };
  if (cookieHeader) headers["cookie"] = cookieHeader;

  const res = await fetch(target, {
    method: "GET",
    headers,
    redirect: "manual",
  });

  // Ingest any Set-Cookie from the response (defence in depth — Fetch 2
  // typically sets none, but if Keycloak ever does we want them logged
  // in the jar in case a follow-up call needs them).
  const setCookies = res.headers.getSetCookie();
  if (setCookies.length > 0) {
    await opts.cookieJar.ingestSetCookie(target, setCookies);
  }

  // Expect a 302 with Location → <callbackUrl>?code=...&state=...
  if (res.status < 300 || res.status >= 400) {
    const body = await safeReadShortBody(res);
    throw new Error(
      `Fetch 2: expected 30x, got ${res.status}. Body snippet: ${body}`,
    );
  }
  const loc = res.headers.get("location");
  await res.body?.cancel().catch(() => undefined);
  if (!loc) {
    throw new Error(`Fetch 2: ${res.status} with no Location header`);
  }
  const locUrl = new URL(loc);
  const code = locUrl.searchParams.get("code");
  const stateOut = locUrl.searchParams.get("state");
  const err = locUrl.searchParams.get("error");
  if (err) {
    const errDesc = locUrl.searchParams.get("error_description") ?? "";
    throw new Error(`Fetch 2: callback error=${err} description=${errDesc}`);
  }
  if (!code || !stateOut) {
    throw new Error(`Fetch 2: Location missing code or state (${redact(loc)})`);
  }
  return { code, state: stateOut };
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function buildAuthorizeUrl(opts: FetchAuthorizeOpts): string {
  const u = new URL(
    `${opts.tcBase.replace(/\/+$/, "")}/realms/${opts.tcRealm}/protocol/openid-connect/auth`,
  );
  u.searchParams.set("client_id", opts.clientId);
  u.searchParams.set("redirect_uri", opts.callbackUrl);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("scope", "openid");
  u.searchParams.set("state", opts.state);
  u.searchParams.set("code_challenge", opts.codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("kc_idp_hint", opts.kcIdpHint);
  return u.toString();
}

/**
 * Heuristic: a SWE URL carries gVVK + voucherURL (and is hosted on a
 * sork-style domain, but we don't pin the host — the realm config might
 * point at a different ORK host). Same predicate the warm-up's
 * oidc.ts uses (`/[?&](gVVK|voucherURL)=/`).
 */
function isSweUrl(url: string): boolean {
  if (!url) return false;
  return /[?&]gVVK=/.test(url) && /[?&]voucherURL=/.test(url);
}

function parseSweUrl(url: string): SweUrlParams {
  const u = new URL(url);
  const raw: Record<string, string> = {};
  for (const [k, v] of u.searchParams.entries()) {
    raw[k] = v;
  }

  // All KNOWN_PARAMS must be present — if any are missing, the SWE URL
  // shape has drifted and the rest of the protocol module won't work.
  const missing = KNOWN_PARAMS.filter((p) => !(p in raw));
  if (missing.length > 0) {
    throw new Error(
      `SWE URL missing required params: ${missing.join(", ")}. ` +
        `Saw: ${Object.keys(raw).join(",")}`,
    );
  }

  return {
    sid:               raw.sid,
    gVVK:              raw.gVVK,
    authorizerPack:    raw.authorizerPack,
    vRedirectUri:      raw.vRedirectUri,
    rURISignature:     raw.rURISignature,
    signedSettings:    raw.signedSettings,
    settingsSignature: raw.settingsSignature,
    gVRKSignature:     raw.gVRKSignature,
    voucherURL:        raw.voucherURL,
    state:             raw.state,
    type:              raw.type,
    raw,
  };
}

/**
 * Read at most a tiny body slice for error messages, without leaking
 * full token-grade payloads if the body happens to be one.
 */
async function safeReadShortBody(res: { text(): Promise<string> }): Promise<string> {
  try {
    const t = await res.text();
    return t.slice(0, 200).replace(/\s+/g, " ");
  } catch {
    return "<unreadable>";
  }
}

/**
 * URL redactor for error messages — keeps origin + path, drops query.
 * Avoids leaking sid / authorizerPack / signatures into logs even on a
 * developer's screen.
 */
function redact(url: string): string {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}?<${u.searchParams.size} params>`;
  } catch {
    return "<unparseable-url>";
  }
}
