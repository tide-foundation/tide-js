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
// the access_token so the warm-up can emit them into the fixture and
// runSign() can optionally refresh on demand in v1.1.
//
// R15: `tideDoken` is the SWE-issued Tide doken (alg=EdDSA, typ=doken).
// TideCloak attaches it as a sibling field of `access_token` on the
// /token response via `AccessTokenResponse.otherClaims` + @JsonAnyGetter
// (TokenManager.java:1406-1408 — `setOtherClaims("doken", encodedTokens[2])`).
// Capturing it here makes the token-exchange the single source for
// tideDoken; the in-page enclave-pump no longer extracts it. The field
// is typed `string | null` so a TideCloak that didn't issue one (e.g.
// non-Tide IdP login somehow reaching this client) is handled cleanly.
//
// SECURITY: refresh_token is more sensitive than access_token — it has a
// longer (often indefinite) lifetime and can mint new access tokens.
// tideDoken is private-equivalent material (bound to the SessionKey).
// Both must NEVER appear in console.log / console.warn / console.error
// / response bodies other than the explicit /warmup/oidc/await/:state
// JSON. See exchangeCodeForToken() and the /warmup/oidc/await/:state
// handler below.
interface TokenResult {
  accessToken: string;
  refreshToken: string | null;
  expiresIn: number | null; // seconds, from token endpoint
  tideDoken: string | null;
}

// Pending OIDC flows keyed by `state`. The /callback handler resolves
// (or rejects) once the token-exchange completes; /warmup/oidc/await
// awaits the same promise.
//
// `sessKeySerialized` is the Option B carve-out side-channel: the
// warm-up driver POSTs it via /warmup/oidc/sesskey/:state when it lifts
// it out of the browser. It's stored on the PendingFlow so
// /warmup/oidc/await/:state can return doken + sessKey + tideDoken
// together. SENSITIVE — private-equivalent material. NEVER log.
//
// `tideDoken` (R15) is no longer captured via the in-page pump. It is
// populated directly from the token-exchange response (TokenResult)
// because TideCloak attaches the SWE-issued Tide doken as a sibling
// `doken` field on /token. We keep the slot on PendingFlow so the
// /warmup/oidc/await/:state response shape is unchanged for callers,
// but the source is the OIDC code-exchange path, not the carve-out POST.
// SENSITIVE — never log.
interface PendingFlow {
  userId: string;
  codeVerifier: string;
  createdAt: number;
  promise: Promise<TokenResult>;
  resolve: (token: TokenResult) => void;
  reject: (err: Error) => void;
  settled: boolean;
  sessKeySerialized: string | null;
  tideDoken: string | null;
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
  // R15: `doken` is a sibling top-level field on TideCloak's /token JSON
  // response — serialized via AccessTokenResponse.otherClaims +
  // @JsonAnyGetter (TokenManager.java:1406-1408,
  // DefaultTokenManager.java:489-555). It carries the SWE-issued Tide
  // doken (alg=EdDSA, typ=doken) that AuthorizedSigningFlow consumes.
  // Defensive typing: if TideCloak didn't issue one we fall through
  // cleanly with `null` rather than throwing — runSign will refuse
  // downstream with a clear error.
  const json = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    doken?: string;
  };
  console.log(`[exchange] /token JSON keys: ${Object.keys(json as object).join(",")}`);
  if (!json.access_token) {
    throw new Error("token endpoint returned no access_token");
  }
  return {
    accessToken: json.access_token,
    refreshToken: typeof json.refresh_token === "string" ? json.refresh_token : null,
    expiresIn: typeof json.expires_in === "number" ? json.expires_in : null,
    tideDoken:
      typeof json.doken === "string" && json.doken.length > 0 ? json.doken : null,
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
    sessKeySerialized: null,
    tideDoken: null,
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
    // SECURITY: do NOT log tokenResult — refresh_token AND tideDoken in
    // particular must stay in-memory and only egress via the explicit
    // /warmup/oidc/await/:state response below.
    //
    // R15: source-of-truth shift for tideDoken. Previously the in-page
    // pump POSTed it via /warmup/oidc/sesskey/:state; we now take it
    // from the token-exchange response and stash it on the PendingFlow
    // here so the /warmup/oidc/await/:state handler can serve it. The
    // carve-out POST may still overwrite `sessKeySerialized`, but it no
    // longer carries tideDoken.
    flow.tideDoken = tokenResult.tideDoken;
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

// Option B carve-out endpoint: deliver the in-browser-captured SWE session
// key (private-equivalent) to the matching pending flow so /warmup/oidc/
// await/:state can return it alongside the OIDC access_token + tideDoken.
//
// R15: the request body is now narrowed to `{ sessKeySerialized }`. The
// `tideDoken` field is no longer part of the contract — the Tide doken
// comes from the token-exchange response (R14 finding: TideCloak attaches
// it as a sibling `doken` field on /token via @JsonAnyGetter). If a stale
// warm-up still sends `tideDoken` in the body, we deliberately ignore it
// — the token-exchange value is authoritative and the in-page enclave
// does not expose a `doken` field in the cmkOnly login flow anyway.
//
// SECURITY:
//   * Realm gate is enforced on the WARM-UP side (oidc.ts) before this is
//     ever called. This endpoint is realm-agnostic — it has no awareness
//     of the configured TIDECLOAK_REALM beyond what the warm-up already
//     refused/permitted. The endpoint is intended for localhost-only use
//     by the warm-up driver in the same process group.
//   * The body field `sessKeySerialized` is private-equivalent material.
//     NEVER log it. Server-side handling is store-and-forward only — we
//     hand it through to the /await response and never to anywhere else.
//   * Single-shot: if a sessKey is already attached to the flow, refuse
//     overwrite (prevents a stray re-POST from clobbering the original).
app.post("/warmup/oidc/sesskey/:state", (req: Request, res: Response) => {
  const state = req.params.state;
  const flow = pending.get(state);
  if (!flow) {
    res
      .status(404)
      .json({ ok: false, code: "UNKNOWN_STATE", message: "unknown state" });
    return;
  }
  const sessKey =
    typeof req.body?.sessKeySerialized === "string"
      ? req.body.sessKeySerialized
      : "";
  if (!sessKey) {
    res
      .status(400)
      .json({ ok: false, code: "BAD_REQUEST", message: "missing sessKeySerialized" });
    return;
  }
  if (flow.sessKeySerialized) {
    res
      .status(409)
      .json({ ok: false, code: "ALREADY_SET", message: "sessKey already captured for this state" });
    return;
  }
  flow.sessKeySerialized = sessKey;
  // R15: deliberately do NOT touch flow.tideDoken here. It's populated
  // from the token-exchange in /callback; a stray `tideDoken` field in
  // this body (from an older warm-up) is ignored.
  // No body echo — defence-in-depth against accidental round-trip logging
  // by the caller's HTTP middleware.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.status(200).json({ ok: true });
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
    // `sessKeySerialized` is the Option B carve-out field — only present
    // if the warm-up driver posted it to /warmup/oidc/sesskey/:state.
    // Sensitive; egress here is the single sanctioned channel (same
    // handling as refreshToken). `doken` is the OIDC access_token from
    // TideCloak's /token endpoint (alg=RS256, typ=JWT); `tideDoken` is
    // the SWE-issued Tide doken (alg=EdDSA, typ=doken) that
    // AuthorizedSigningFlow's constructor consumes. They are NOT
    // interchangeable — see runSign.ts and R11/R14's findings.
    //
    // R15: `tideDoken` is now sourced from the token-exchange response
    // (sibling `doken` field on TideCloak's /token JSON, attached via
    // @JsonAnyGetter) rather than the in-page enclave pump. Still
    // sensitive; never log.
    res.json({
      ok: true,
      userId: flow.userId,
      doken: tokenResult.accessToken,
      refreshToken: tokenResult.refreshToken,
      expiresInSeconds: tokenResult.expiresIn,
      sessKeySerialized: flow.sessKeySerialized,
      tideDoken: flow.tideDoken,
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
