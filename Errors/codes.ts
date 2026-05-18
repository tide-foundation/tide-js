//
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
//
// This program is free software and is subject to the terms of
// the Tide Community Open Code License as published by the
// Tide Foundation Limited. You may modify it and redistribute
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind,
// including without any implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

/**
 * Canonical error codes emitted by tide-js itself.
 *
 * Format: `TIDE-TIDEJS-<CATEGORY>-<NAME>`
 *
 * These are *only* the codes tide-js originates. When tide-js receives an
 * `application/problem+json` body from an upstream component (e.g. ORK,
 * tidecloak-idp-extensions), the upstream `code` is passed through verbatim
 * on the resulting `TideError` and is NOT mapped onto any of these constants.
 */
export const TideJsErrorCodes = Object.freeze({
    // --- Network ---------------------------------------------------------
    /** Underlying `fetch` rejected (DNS, connection refused, TLS, CORS, ...). */
    NET_FETCH_FAILED: "TIDE-TIDEJS-NET-FETCH_FAILED",
    /** The request was aborted by our internal `setTimeout(...controller.abort)`. */
    NET_TIMEOUT: "TIDE-TIDEJS-NET-TIMEOUT",
    /** The request was aborted by a caller-supplied `AbortSignal`. */
    NET_ABORTED: "TIDE-TIDEJS-NET-ABORTED",
    /** `response.ok === false` and the body did not carry a recognisable error envelope. */
    NET_NON_OK_STATUS: "TIDE-TIDEJS-NET-NON_OK_STATUS",
    /**
     * Fan-out to multiple ORKs completed but fewer succeeded than the
     * threshold required (e.g. 3 of 5 ORKs unreachable during a sign flow).
     * Carries `details[]` with each per-ORK underlying failure.
     */
    NET_THRESHOLD_FAILURE: "TIDE-TIDEJS-NET-THRESHOLD_FAILURE",

    // --- Parsing ---------------------------------------------------------
    /** Server sent `application/problem+json` but the body did not parse / lacked required fields. */
    PARSE_PROBLEM_JSON_INVALID: "TIDE-TIDEJS-PARSE-PROBLEM_JSON_INVALID",
    /** Body shape is not understood (e.g. legacy `--FAILED--:` envelope, or unknown format). */
    PARSE_UNKNOWN_FORMAT: "TIDE-TIDEJS-PARSE-UNKNOWN_FORMAT",
    /** A NodeClient response did not contain the expected `index` field (used by `WaitForNumberofORKs` cleanup). */
    PARSE_NODECLIENT_RESPONSE_SHAPE: "TIDE-TIDEJS-PARSE-NODECLIENT_RESPONSE_SHAPE",
    /** TideMemory buffer is too small to read the requested segment (truncated / malformed input). */
    PARSE_INSUFFICIENT_DATA: "TIDE-TIDEJS-PARSE-INSUFFICIENT_DATA",
    /** TideMemory segment index requested is past the end of the buffer's encoded segments. */
    PARSE_INDEX_OUT_OF_RANGE: "TIDE-TIDEJS-PARSE-INDEX_OUT_OF_RANGE",
    /** TideMemory allocation/write would exceed the destination buffer's capacity. */
    PARSE_BUFFER_OVERFLOW: "TIDE-TIDEJS-PARSE-BUFFER_OVERFLOW",

    // --- Validation ------------------------------------------------------
    /** A client method required a session key but `AddBearerAuthorization` was never called. */
    VAL_MISSING_SESSION_KEY: "TIDE-TIDEJS-VAL-MISSING_SESSION_KEY",
    /** A flow input failed a shape/type validation (wrong type, wrong array length, missing required field). */
    VAL_INPUT_SHAPE: "TIDE-TIDEJS-VAL-INPUT_SHAPE",
    /** The supplied username (uid) is not allowed (empty reserver list returned by the network). */
    VAL_UID_FORBIDDEN: "TIDE-TIDEJS-VAL-UID_FORBIDDEN",
    /** The supplied account could not be located on the network (e.g. simulator invalid-account sentinel). */
    VAL_INVALID_ACCOUNT: "TIDE-TIDEJS-VAL-INVALID_ACCOUNT",

    // --- Crypto ----------------------------------------------------------
    /** The session key the caller supplied does not match the session key bound into the Doken. */
    CRYPTO_SESSION_KEY_MISMATCH: "TIDE-TIDEJS-CRYPTO-SESSION_KEY_MISMATCH",
    /** GRj and Sj arrays produced by a signing flow had differing lengths (should be impossible). */
    CRYPTO_GRJ_SJ_LENGTH_MISMATCH: "TIDE-TIDEJS-CRYPTO-GRJ_SJ_LENGTH_MISMATCH",
    /** Per-ORK response arrays had differing lengths during PreSign/Sign aggregation. */
    CRYPTO_ORK_ARRAY_LENGTH_MISMATCH: "TIDE-TIDEJS-CRYPTO-ORK_ARRAY_LENGTH_MISMATCH",

    // --- Signature -------------------------------------------------------
    /** Local blind-signature verification failed against the expected challenge. */
    SIG_BLIND_VERIFY_FAILED: "TIDE-TIDEJS-SIG-BLIND_VERIFY_FAILED",

    // --- Proxy / pass-through -------------------------------------------
    /**
     * tide-js is wrapping an upstream failure in a way that *adds* semantics
     * (e.g. "all ORKs failed", retry exhaustion). For straight pass-through
     * of an upstream Problem Details body, DO NOT use this — preserve the
     * upstream `code` verbatim instead.
     */
    PROXY_UPSTREAM_ERROR: "TIDE-TIDEJS-PROXY-UPSTREAM_ERROR",
} as const);

export type TideJsErrorCode = typeof TideJsErrorCodes[keyof typeof TideJsErrorCodes];
