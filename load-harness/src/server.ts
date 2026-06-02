//
// tide-load-harness Express server.
//
// Two responsibilities:
//
//  1. /run/sign — Locust posts a UserFixture; we drive one
//     AuthorizedSigningFlow.signv2() against the live ORK network and
//     return the per-iteration status + latency.
//
//  2. OIDC code-flow capture for the Playwright warm-up. The warm-up
//     calls POST /warmup/oidc/begin to mint a (state, code_verifier)
//     pair and get back the Keycloak authorize URL. Playwright then
//     drives the SWE login in a browser; on success TideCloak
//     redirects to http://localhost:3000/callback?code=...&state=...
//     which we exchange for an access_token. The access_token IS the
//     Tide Doken (TideCloak's broker-issued token after SWE CMK auth
//     completes). GET /warmup/oidc/await/:state long-polls until the
//     token is captured.
//
import "./shims.js";
import express, { type Request, type Response } from "express";
import { randomBytes, createHash } from "node:crypto";
import { runSign, type RealmFixture, type UserFixture } from "./runSign.js";
import { loadFixtures, type LoadedFixtures } from "./fixtures.js";

const port = Number(process.env.PORT ?? 3000);
const fixturesPath = process.env.FIXTURES_PATH ?? "./fixtures.json";

// Strip any trailing slash so `${tcBase}/realms/...` never produces `//realms/...`.
const tcBase = (process.env.TIDECLOAK_BASE_URL ?? "https://staging.dauth.me").replace(
  /\/+$/,
  "",
);
const tcRealm = process.env.TIDECLOAK_REALM ?? "tide-metrics-load";
const oidcClientId = process.env.OIDC_CLIENT_ID ?? "tide-loadtest-harness";
const callbackUrl =
  process.env.OIDC_REDIRECT_URI ?? `http://localhost:${port}/callback`;

const PENDING_TTL_MS = 5 * 60 * 1000;
const REAPER_INTERVAL_MS = 30 * 1000;
// Cap concurrent in-flight OIDC flows so a malicious or runaway warm-up
// loop can't exhaust memory by spamming /warmup/oidc/begin.
const MAX_PENDING_FLOWS = 1000;

// Token-endpoint result. We capture refresh_token + expires_in alongside
// the access_token (the Doken) so the warm-up can emit them into the
// fixture and runSign() can optionally refresh on demand in v1.1.
//
// SECURITY: refresh_token is more sensitive than access_token — it has a
// longer (often indefinite) lifetime and can mint new access tokens.
// Treat it as a secret: it must NEVER appear in console.log /
// console.warn / console.error / response bodies other than the explicit
// /warmup/oidc/await/:state JSON. See exchangeCodeForToken() and the
// /warmup/oidc/await/:state handler below.
interface TokenResult {
  accessToken: string;
  refreshToken: string | null;
  expiresIn: number | null; // seconds, from token endpoint
}

// Pending OIDC flows keyed by `state`. The /callback handler resolves
// (or rejects) once the token-exchange completes; /warmup/oidc/await
// awaits the same promise.
interface PendingFlow {
  userId: string;
  codeVerifier: string;
  createdAt: number;
  promise: Promise<TokenResult>;
  resolve: (token: TokenResult) => void;
  reject: (err: Error) => void;
  settled: boolean;
}
const pending = new Map<string, PendingFlow>();

function b64url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function newCodeVerifier(): string {
  return b64url(randomBytes(32));
}

function codeChallengeS256(verifier: string): string {
  return b64url(createHash("sha256").update(verifier).digest());
}

function newState(): string {
  return b64url(randomBytes(16));
}

function reapExpired() {
  const now = Date.now();
  for (const [state, flow] of pending) {
    if (now - flow.createdAt > PENDING_TTL_MS) {
      if (!flow.settled) flow.reject(new Error("oidc flow expired"));
      pending.delete(state);
    }
  }
}

// Minimal HTML escaper for the small set of values we reflect into the
// /callback response (Keycloak's `error` param, exception messages).
// Keycloak emits values from a controlled allowlist, but defence-in-depth.
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      case "'":
        return "&#39;";
      default:
        return c;
    }
  });
}

function buildAuthorizeUrl(state: string, codeChallenge: string): string {
  const u = new URL(
    `${tcBase}/realms/${tcRealm}/protocol/openid-connect/auth`,
  );
  u.searchParams.set("client_id", oidcClientId);
  u.searchParams.set("redirect_uri", callbackUrl);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("scope", "openid");
  u.searchParams.set("state", state);
  u.searchParams.set("code_challenge", codeChallenge);
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("kc_idp_hint", "tide");
  return u.toString();
}

async function exchangeCodeForToken(
  code: string,
  codeVerifier: string,
): Promise<TokenResult> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: callbackUrl,
    client_id: oidcClientId,
    code_verifier: codeVerifier,
  });
  const res = await fetch(
    `${tcBase}/realms/${tcRealm}/protocol/openid-connect/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    },
  );
  if (!res.ok) {
    // SECURITY: the token-endpoint error body is reflected in the thrown
    // message; on the success path no token material is logged. The
    // truncation (slice 500) bounds blast radius if Keycloak ever
    // echoes part of the request back. Do NOT add logging of `json`
    // below — refresh_token in particular must never hit the console.
    const text = await res.text();
    throw new Error(`token endpoint ${res.status}: ${text.slice(0, 500)}`);
  }
  const json = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
  };
  if (!json.access_token) {
    throw new Error("token endpoint returned no access_token");
  }
  return {
    accessToken: json.access_token,
    refreshToken: typeof json.refresh_token === "string" ? json.refresh_token : null,
    expiresIn: typeof json.expires_in === "number" ? json.expires_in : null,
  };
}

// Fixtures are optional at boot — the warm-up runs before any
// fixtures.json exists. Load lazily; /run/sign 503s if absent. We
// distinguish "file genuinely missing" (warm-up hasn't run yet) from
// "file present but malformed" (a real config bug worth surfacing
// loudly) so an operator notices a corrupt fixtures.json.
//
// loaded.users is the per-user fixture list; loaded.realm holds the
// realm-level public state (vvkid, vvkPublic, orks, voucherURL,
// homeOrkUrl) shared across every user. Both are required by runSign().
let loaded: LoadedFixtures | null = null;
try {
  loaded = await loadFixtures(fixturesPath);
} catch (e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  const isMissing =
    typeof e === "object" && e !== null && (e as { code?: unknown }).code === "ENOENT";
  if (isMissing) {
    console.warn(
      `[harness] fixtures file not present at ${fixturesPath} — /run/sign will 503 until warm-up writes it`,
    );
  } else {
    console.error(
      `[harness] fixtures present but FAILED TO LOAD from ${fixturesPath}: ${msg}`,
    );
  }
}

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req: Request, res: Response) => {
  res.json({
    ok: true,
    fixturesLoaded: loaded?.users.length ?? 0,
    realmLoaded: loaded?.realm.realm ?? null,
    pendingOidcFlows: pending.size,
    tcBase,
    tcRealm,
    oidcClientId,
    callbackUrl,
  });
});

app.post("/run/sign", async (req: Request, res: Response) => {
  if (!loaded) {
    res.status(503).json({
      ok: false,
      code: "NO_FIXTURES",
      message: `fixtures not loaded from ${fixturesPath}`,
    });
    return;
  }
  // Locust passes only the per-user fixture; the harness holds the
  // realm fixture in module scope (it is identical for every user) and
  // forwards both into runSign().
  const fixture = req.body?.fixture as UserFixture | undefined;
  if (!fixture) {
    res.status(400).json({
      ok: false,
      code: "BAD_REQUEST",
      message: "missing fixture",
    });
    return;
  }
  const result = await runSign(fixture, loaded.realm);
  res.status(result.ok ? 200 : 500).json(result);
});

//
// OIDC warm-up endpoints
//

// Begin a new flow: returns { authUrl, state }.  The caller (warm-up
// Playwright script) navigates a browser to authUrl and signs in via
// the SWE; we capture the resulting redirect at /callback.
app.post("/warmup/oidc/begin", (req: Request, res: Response) => {
  reapExpired();
  const userId =
    typeof req.body?.userId === "string" ? req.body.userId.trim() : "";
  if (!userId) {
    res
      .status(400)
      .json({ ok: false, code: "BAD_REQUEST", message: "missing userId" });
    return;
  }
  if (pending.size >= MAX_PENDING_FLOWS) {
    res.status(429).json({
      ok: false,
      code: "TOO_MANY_PENDING",
      message: `at limit (${MAX_PENDING_FLOWS}) of in-flight oidc flows`,
    });
    return;
  }
  const state = newState();
  const codeVerifier = newCodeVerifier();
  const codeChallenge = codeChallengeS256(codeVerifier);

  let resolveFn!: (t: TokenResult) => void;
  let rejectFn!: (e: Error) => void;
  const promise = new Promise<TokenResult>((resolve, reject) => {
    resolveFn = resolve;
    rejectFn = reject;
  });
  const flow: PendingFlow = {
    userId,
    codeVerifier,
    createdAt: Date.now(),
    promise,
    resolve: (t: TokenResult) => {
      if (flow.settled) return;
      flow.settled = true;
      resolveFn(t);
    },
    reject: (e) => {
      if (flow.settled) return;
      flow.settled = true;
      rejectFn(e);
    },
    settled: false,
  };
  // Swallow unhandled-rejection if /warmup/oidc/await/:state is never
  // called for an expired/failed flow — the reaper or /callback may
  // reject the promise with no awaiter attached, which would otherwise
  // log a noisy UnhandledPromiseRejection.
  promise.catch(() => {});
  pending.set(state, flow);

  res.json({ ok: true, state, authUrl: buildAuthorizeUrl(state, codeChallenge) });
});

// TideCloak redirects the browser here after the SWE login completes.
// We exchange the code for an access_token (the Doken) and resolve the
// pending promise so /warmup/oidc/await unblocks.
app.get("/callback", async (req: Request, res: Response) => {
  // Express parses repeated query params into arrays; coerce to single
  // strings and reject anything else so we never `String([...])` an array.
  const code = typeof req.query.code === "string" ? req.query.code : "";
  const state = typeof req.query.state === "string" ? req.query.state : "";
  const error =
    typeof req.query.error === "string" && req.query.error.length > 0
      ? req.query.error
      : null;
  const errorDescription =
    typeof req.query.error_description === "string"
      ? req.query.error_description
      : "";

  // /callback responses must not be cached (defence-in-depth — they
  // contain a userId reflected from server state).
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  const flow = state ? pending.get(state) : undefined;

  if (error) {
    if (flow) flow.reject(new Error(`oidc error: ${error}: ${errorDescription}`));
    res
      .status(400)
      .send(
        `<html><body>OIDC error: ${escapeHtml(error)}${
          errorDescription ? ` (${escapeHtml(errorDescription)})` : ""
        }. You can close this tab.</body></html>`,
      );
    return;
  }
  if (!state) {
    res
      .status(400)
      .send(`<html><body>Missing state parameter. You can close this tab.</body></html>`);
    return;
  }
  if (!flow) {
    // CSRF / replay protection: an unknown state means either a stale
    // callback from a previous server lifetime, a TTL expiry, or an
    // attacker forging a redirect. In all cases, refuse.
    res
      .status(400)
      .send(
        `<html><body>Unknown or expired state. You can close this tab.</body></html>`,
      );
    return;
  }
  if (flow.settled) {
    // Defence-in-depth: ignore re-deliveries of the same callback (e.g.
    // user reloads the tab). The code is single-use at the token
    // endpoint anyway, but don't re-attempt or overwrite the result.
    res
      .status(200)
      .send(`<html><body>Already captured. You can close this tab.</body></html>`);
    return;
  }
  if (!code) {
    flow.reject(new Error("callback missing code"));
    res
      .status(400)
      .send(`<html><body>Missing code parameter. You can close this tab.</body></html>`);
    return;
  }

  try {
    const tokenResult = await exchangeCodeForToken(code, flow.codeVerifier);
    // SECURITY: do NOT log tokenResult — refresh_token in particular
    // must stay in-memory and only egress via the explicit
    // /warmup/oidc/await/:state response below.
    flow.resolve(tokenResult);
    res
      .status(200)
      .send(
        `<html><body>Login captured for ${escapeHtml(
          flow.userId,
        )}. You can close this tab.</body></html>`,
      );
  } catch (e: unknown) {
    const err = e instanceof Error ? e : new Error(String(e));
    flow.reject(err);
    res
      .status(500)
      .send(
        `<html><body>Token exchange failed: ${escapeHtml(
          err.message,
        )}. You can close this tab.</body></html>`,
      );
  }
});

// Long-poll until the matching /callback resolves the flow.  Returns
// { doken } on success.  The warm-up script awaits this after kicking
// off Playwright on authUrl.
app.get("/warmup/oidc/await/:state", async (req: Request, res: Response) => {
  const state = req.params.state;
  const flow = pending.get(state);
  if (!flow) {
    res
      .status(404)
      .json({ ok: false, code: "UNKNOWN_STATE", message: "unknown state" });
    return;
  }
  try {
    const tokenResult = await flow.promise;
    // SECURITY: this is the ONE sanctioned egress point for
    // refresh_token. Caller is the local warm-up script over localhost
    // only; the Cache-Control: no-store header prevents any intermediary
    // (browser, dev-tool proxy) from caching the body. Do NOT add
    // logging of tokenResult.refreshToken anywhere downstream.
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    res.json({
      ok: true,
      userId: flow.userId,
      doken: tokenResult.accessToken,
      refreshToken: tokenResult.refreshToken,
      expiresInSeconds: tokenResult.expiresIn,
    });
  } catch (e: unknown) {
    res.status(500).json({
      ok: false,
      code: "OIDC_FAILED",
      message: e instanceof Error ? e.message : String(e),
    });
  } finally {
    // Always drop the entry once the awaiter has drained the result —
    // settled or not — so we don't accumulate state across the warm-up
    // loop. If multiple awaiters race, the loser will see UNKNOWN_STATE.
    pending.delete(state);
  }
});

// Periodic reaper so expired flows are cleaned even if no new /begin
// traffic arrives. `.unref()` lets Node exit cleanly on SIGINT.
const reaperTimer = setInterval(reapExpired, REAPER_INTERVAL_MS);
reaperTimer.unref?.();

app.listen(port, () => {
  console.log(
    `tide-load-harness on :${port} — users=${loaded?.users.length ?? 0} realm=${loaded?.realm.realm ?? "<none>"} tc=${tcBase}/realms/${tcRealm} client=${oidcClientId}`,
  );
});
