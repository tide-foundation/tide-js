//
// NodeCmkClient — pure-Node driver for the cmkOnly login flow.
//
// R4 (this file): full end-to-end protocol path.
//   1. Fetch 1 → SWE URL params + KC_AUTH_SESSION_HASH cookie. (R3.)
//   2. Mint fresh ephemeral session keys per VU.
//   3. Look up KeyInfo for the user on the home ORK.
//   4. Drive dCMKPasswordFlow.Convert (ORK fan-out, PRISM + CMK convert)
//      then .Authenticate (ORK fan-out, blind-signed auth token + ElGamal
//      encrypt to gVRK from the SWE's authorizerPack).
//   5. Fetch 2 → terminal GET to vRedirectUri with vendorEncryptedData,
//      returning the OIDC `code` + `state` parsed from the 302 Location.
//
// We deliberately STOP after parsing `code`+`state`. Exchanging the code
// for an access_token is the existing /callback path in server.ts and is
// not needed for raw-protocol load testing (see R19 parking lot in the
// load-test memory note).
//
// SECURITY:
//   * The cmkOnly flow never sends `password` to TideCloak in cleartext.
//     The egress is inside the ORK Convert call — the user's password is
//     transformed into a Point via HashToPoint and blurred by a random
//     scalar before any network call. We MUST NOT log:
//       - user.password (in any form)
//       - sessionKey / networkSessionKey private bytes
//       - vendorEncryptedData
//       - the captured OIDC `code`
//   * Per-VU cookie jars (cookie-jar.ts) and per-VU sessionKey/
//     networkSessionKey provide isolation. No shared mutable state.
//

import "./undici-setup.js";
import { randomBytes, createHash } from "node:crypto";

import { createCookieJar } from "./cookie-jar.js";
import { fetchAuthorize, fetchBrokerCallback } from "./tideAuth.js";
import type { LoginResult, SweUrlParams } from "./types.js";
import type { RealmFixture } from "../runSign.js";

// Pull tide-js building blocks via the workspace alias. Same import shape
// the existing harness code (runSign.ts) uses.
import { Cryptide, Clients } from "@tideorg/js";
const { TideKey } = Cryptide as any;
const { Schemes } = (Cryptide as any).Components;
const Ed25519Scheme = Schemes.Ed25519.Ed25519Scheme;
const { GetUID, Hex2Bytes, AuthorizerPack, DeserializeNetworkKey } = (Cryptide as any).Serialization;
const { HashToPoint } = (Cryptide as any).Hashing;

// Local ork copies (R4 port).
// @ts-expect-error — .js file, no .d.ts; consumed at runtime via esbuild bundle.
import dCMKPasswordFlow from "./ork/Flows/AuthenticationFlows/dCMKPasswordFlow.js";

/**
 * Minimal user shape consumed by NodeCmkClient. The full UserFixture
 * (with vuid/doken/etc.) is only relevant for the post-login Sign flow
 * and not needed for login itself — we only need credentials.
 */
export interface CmkLoginUser {
  userId:   string;
  password: string;
}

export interface NodeCmkClientOpts {
  tcBase:      string;
  tcRealm:     string;
  clientId:    string;
  callbackUrl: string;
  /** Home ORK base URL — used to fetch KeyInfo. Mirrors the warm-up's
   *  WARMUP_HOME_ORK convention. */
  homeOrkUrl:  string;
  /** "tide" in every observed deployment; included so a future test
   *  realm with a different IdP alias can still drive this client. */
  kcIdpHint?:  string;
}

export class NodeCmkClient {
  private readonly tcBase:      string;
  private readonly tcRealm:     string;
  private readonly clientId:    string;
  private readonly callbackUrl: string;
  private readonly homeOrkUrl:  string;
  private readonly kcIdpHint:   string;

  constructor(opts: NodeCmkClientOpts) {
    this.tcBase      = opts.tcBase.replace(/\/+$/, "");
    this.tcRealm     = opts.tcRealm;
    this.clientId    = opts.clientId;
    this.callbackUrl = opts.callbackUrl;
    this.homeOrkUrl  = opts.homeOrkUrl.replace(/\/+$/, "");
    this.kcIdpHint   = opts.kcIdpHint ?? "tide";
  }

  /**
   * Drive one cmkOnly login flow end-to-end.
   *
   * `realm` is the same RealmFixture the warm-up writes. R4 reads
   * homeOrkUrl from `this.homeOrkUrl` (not the fixture) so the protocol
   * smoke CLI can run without a pre-existing fixtures.json — the fixture
   * is only used for diagnostic context (realm name in logs).
   */
  async login(user: CmkLoginUser, realm: RealmFixture): Promise<LoginResult> {
    const start = performance.now();
    const phases: LoginResult["phases"] = { totalMs: 0 };
    try {
      const jar = createCookieJar();
      const oidcState   = b64url(randomBytes(16));
      const codeVerifier = b64url(randomBytes(32));
      const codeChallenge = b64url(
        createHash("sha256").update(codeVerifier).digest(),
      );

      // --- Fetch 1 ---
      const t1 = performance.now();
      const sweParams: SweUrlParams = await fetchAuthorize({
        tcBase:        this.tcBase,
        tcRealm:       this.tcRealm,
        clientId:      this.clientId,
        callbackUrl:   this.callbackUrl,
        state:         oidcState,
        codeChallenge,
        kcIdpHint:     this.kcIdpHint,
        cookieJar:     jar,
      });
      phases.fetch1Ms = Math.round(performance.now() - t1);

      const kcAuthHash = await jar.getValue(
        `${this.tcBase}/realms/${this.tcRealm}/`,
        "KC_AUTH_SESSION_HASH",
      );
      if (!kcAuthHash) {
        // Without KC_AUTH_SESSION_HASH the Fetch 2 callback will be
        // rejected by TideCloak. Surface this as an explicit failure
        // BEFORE running the (expensive) crypto fan-out.
        const totalMs = Math.round(performance.now() - start);
        phases.totalMs = totalMs;
        return {
          ok: false,
          durationMs: totalMs,
          phases,
          message:
            "Fetch 1 returned SWE params but KC_AUTH_SESSION_HASH cookie was NOT captured. Cookie jar / hop sequence broken.",
        };
      }

      // --- Crypto fan-out ---
      const cryptoT0 = performance.now();
      const vendorEncryptedData = await runCryptoFlow({
        userId:     user.userId,
        password:   user.password,
        sweParams,
        homeOrkUrl: this.homeOrkUrl,
      });
      phases.cryptoMs = Math.round(performance.now() - cryptoT0);

      // --- Fetch 2 ---
      const fetch2T0 = performance.now();
      const { code, state: returnedState } = await fetchBrokerCallback({
        vRedirectUri:        sweParams.vRedirectUri,
        state:               sweParams.state,
        vendorEncryptedData,
        cookieJar:           jar,
      });
      phases.fetch2Ms = Math.round(performance.now() - fetch2T0);

      const totalMs = Math.round(performance.now() - start);
      phases.totalMs = totalMs;
      return {
        ok:         true,
        durationMs: totalMs,
        phases,
        code,
        state:      returnedState,
        message:    `R4 end-to-end OK on realm=${realm.realm}`,
      };
    } catch (e) {
      const totalMs = Math.round(performance.now() - start);
      phases.totalMs = totalMs;
      const raw = e instanceof Error ? (e.stack ?? e.message) : String(e);
      return {
        ok:         false,
        durationMs: totalMs,
        phases,
        // Defensive redaction — password should never be in any thrown
        // message, but if a copy-paste regression ever puts it there, we
        // scrub on the way out.
        message:    redactPwd(raw, user.password),
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Crypto orchestration (mirrors EnclaveBase._authenticate lines 146-178).
// ---------------------------------------------------------------------------

interface RunCryptoFlowOpts {
  userId:     string;
  password:   string;
  sweParams:  SweUrlParams;
  homeOrkUrl: string;
}

/**
 * Run the in-enclave Convert + Authenticate sequence for one cmkOnly
 * login. Returns the base64-encoded vendorEncryptedData that the SWE
 * normally hands back to TideCloak in the Fetch 2 redirect.
 *
 * This is the Node-side equivalent of the browser CMKOnlyEnclave +
 * EnclaveBase._authenticate sequence. We DO NOT run the QR-code or
 * passwordless paths — those are gated by `cmkOnly` enclave type and the
 * EnclaveEntry branch in EnclaveBase, which we never hit.
 */
async function runCryptoFlow(opts: RunCryptoFlowOpts): Promise<string> {
  const { userId, password, sweParams, homeOrkUrl } = opts;

  // 1. Mint fresh ephemerals.
  //    `networkSessionKey` — feeds the per-ORK PRISM ECDH so each ORK gets
  //    a different `prkECDHi` to wrap selfRequesti.
  //    `sessionKey` — the SWE's "user-visible" session key; in the browser
  //    this is the long-lived key on the enclave, but on a single-shot VU
  //    we mint fresh per iteration (we never persist or reuse).
  const networkSessionKey = TideKey.NewKey(Ed25519Scheme);
  const sessionKey        = TideKey.NewKey(Ed25519Scheme);

  // 2. UID = SHA256(userId) (Cryptide.Serialization.GetUID).
  const uid = await GetUID(userId);

  // 3. Look up the user's KeyInfo on the home ORK. This returns the
  //    cohort (OrkInfo[]) plus UserPublic (gCMK) and UserM that the
  //    Convert step requires.
  const simClient = new (Clients as any).NetworkClient(homeOrkUrl);
  const keyInfo   = await simClient.GetKeyInfo(uid);

  // 4. HashToPoint(password) → gPass. Same call the SWE does inline
  //    while waiting for KeyInfo.
  const gPass = await HashToPoint(password);

  // 5. Parse the SWE-issued authorizerPack to recover gVRK (the vendor
  //    rotating public key). Path:
  //      authorizerPack (hex string) → Hex2Bytes → AuthorizerPack →
  //      .Authorizer.GVRK (Ed25519PublicComponent) → .public (Point).
  const authorizerPackBytes = Hex2Bytes(sweParams.authorizerPack);
  const authorizerPack      = new AuthorizerPack(authorizerPackBytes);
  const gVRK                = authorizerPack.Authorizer.GVRK.public;

  // (gVVK is also on the SWE URL — DeserializeNetworkKey(gVVK) is the
  // _vendorPublic in EnclaveBase. The cmkOnly Convert/Authenticate path
  // does NOT actually need gVVK; it's used by CMKOnlyEnclave for URL
  // signature verification, which we skip in the load harness. We still
  // parse it here to confirm the value is well-formed — a bad gVVK on the
  // URL would otherwise only blow up at Fetch 2 with a confusing error.)
  DeserializeNetworkKey(sweParams.gVVK);

  // 6. Build the dCMKPasswordFlow. cmkCommitted=true, prismCommitted=true
  //    match the SWE's _authenticate call (account is already committed
  //    by the warm-up Path-α run).
  const flow = new dCMKPasswordFlow(
    keyInfo,
    sweParams.sid,
    /*cmkCommitted*/   true,
    /*prismCommitted*/ true,
    sweParams.voucherURL,
  );

  // 7. Convert — ORK fan-out. rememberMe=false (no per-VU storage),
  //    clientDPoPKey=null (DPoP is not on this load path).
  await flow.Convert(
    networkSessionKey,
    gPass,
    keyInfo.UserPublic,
    /*rememberMe*/        false,
    /*vendorSessionKey*/  sessionKey,
    /*clientDPoPKey*/     null,
  );

  // 8. Authenticate — ORK fan-out, returns ElGamal-encrypted VendorData
  //    targetted at gVRK.
  const { vendorEncryptedData } = await flow.Authenticate(gVRK);
  if (typeof vendorEncryptedData !== "string" || vendorEncryptedData.length === 0) {
    throw new Error("Crypto flow returned empty vendorEncryptedData");
  }
  return vendorEncryptedData;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function b64url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function redactPwd(s: string, password: string): string {
  if (!password || password.length < 3) return s;
  const enc = encodeURIComponent(password);
  return s.split(password).join("[REDACTED]").split(enc).join("[REDACTED]");
}
