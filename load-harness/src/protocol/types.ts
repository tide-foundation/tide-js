//
// Shared types for the browserless cmkOnly protocol module.
//
// SweUrlParams mirrors the URL the SWE host (sork*.tideprotocol.com) is
// redirected to at the end of the kc_idp_hint=tide chain. R2 preflight
// captured these field names verbatim from the live `tide-metrics-load`
// realm on staging. The shape is also used by the in-browser
// CMKOnlyEnclave (ork-Enclave EnclaveBase._authenticate, lines 146-178)
// — when R4 ports the crypto, the same names will flow into NodeClient.
//

/**
 * The parameters carried on the SWE-side URL after the kc_idp_hint=tide
 * chain (TideCloak `auth` -> `broker/tide/login` -> sork SWE URL).
 *
 * `state` is the inner SWE state (NOT the OIDC `state` from the original
 * /auth request — that one is regenerated downstream). All other fields
 * are server-issued and treated as opaque on the client.
 */
export interface SweUrlParams {
  sid:               string;   // SWE session id, signed server-side; cannot be minted client-side
  gVVK:              string;   // realm vendor public key (hex)
  authorizerPack:    string;
  vRedirectUri:      string;   // absolute URL we POST to for Fetch 2
  rURISignature:     string;
  signedSettings:    string;
  settingsSignature: string;
  gVRKSignature:     string;
  voucherURL:        string;   // ORK voucher endpoint (with sessionId/tabId tokens)
  state:             string;   // inner SWE state (echoed back in Fetch 2)
  type:              string;   // "cmkOnly" for this flow
  /**
   * Full set of name=value pairs observed on the SWE URL during R2
   * preflight. Kept for diagnostic + R4-cryptopath use (CMKOnlyEnclave
   * iterates over this list when assembling per-flow inputs).
   */
  raw:               Record<string, string>;
}

/**
 * Canonical list of SWE URL params the cmkOnly flow knows how to
 * interpret. R2 preflight observed all 11 of these on every fresh
 * /auth?... navigation against the live staging realm. R4 will use
 * this list to assert presence at parse time.
 */
export const KNOWN_PARAMS = [
  "sid",
  "gVVK",
  "authorizerPack",
  "vRedirectUri",
  "rURISignature",
  "signedSettings",
  "settingsSignature",
  "gVRKSignature",
  "voucherURL",
  "state",
  "type",
] as const;

export type KnownParam = typeof KNOWN_PARAMS[number];

/**
 * Per-iteration result returned by `NodeCmkClient.login`.
 *
 * `phases` mirrors the v1 loadtest/index.ts PhaseTimings split but is
 * coarser (only fetch1 / crypto / fetch2 / total) — the cryptide port in
 * R4 may add per-RTT sub-phases (voucher, convert, authenticate) if the
 * extra granularity proves useful.
 */
export interface LoginResult {
  ok:         boolean;
  durationMs: number;
  phases: {
    fetch1Ms?: number;
    cryptoMs?: number;
    fetch2Ms?: number;
    totalMs:   number;
  };
  /** OIDC `code` parsed from the terminal 302 Location header. */
  code?:    string;
  /** OIDC `state` parsed from the terminal 302 Location header. */
  state?:   string;
  /** Brief, password-scrubbed error message when ok=false. */
  message?: string;
}
