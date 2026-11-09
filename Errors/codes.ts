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

    // --- Network (additional) -------------------------------------------
    /** A non-TideError value was thrown from the fetch pipeline — caught and tagged for the recent-requests buffer. */
    NET_UNKNOWN: "TIDE-TIDEJS-NET-UNKNOWN",

    // --- Cryptide / low-level crypto ------------------------------------
    /** A `BaseComponent` abstract method (e.g. `Add`/`Multiply`/`Scheme`) was invoked but not implemented on the concrete subclass. */
    CRYPTO_NOT_IMPLEMENTED: "TIDE-TIDEJS-CRYPTO-NOT_IMPLEMENTED",
    /** Two components were combined whose schemes / component-types do not match. */
    CRYPTO_COMPONENT_MISMATCH: "TIDE-TIDEJS-CRYPTO-COMPONENT_MISMATCH",
    /** Scheme / component-type registry lookup failed (unknown scheme or component type). */
    CRYPTO_UNKNOWN_COMPONENT_TYPE: "TIDE-TIDEJS-CRYPTO-UNKNOWN_COMPONENT_TYPE",
    /** A serialized component could not be parsed into bytes (neither hex nor base64). */
    CRYPTO_DESERIALIZE_FAILED: "TIDE-TIDEJS-CRYPTO-DESERIALIZE_FAILED",
    /** AES encrypt/decrypt called with a key of an unsupported JS type. */
    CRYPTO_AES_UNSUPPORTED_KEY_TYPE: "TIDE-TIDEJS-CRYPTO-AES_UNSUPPORTED_KEY_TYPE",
    /** DH `computeSharedKey` called with a private value of an unsupported JS type. */
    CRYPTO_DH_UNSUPPORTED_PRIV_TYPE: "TIDE-TIDEJS-CRYPTO-DH_UNSUPPORTED_PRIV_TYPE",
    /** An Ed25519 Point failed an on-curve / equality / non-ZERO sanity check. */
    CRYPTO_ED25519_BAD_POINT: "TIDE-TIDEJS-CRYPTO-ED25519_BAD_POINT",
    /** Modular inverse does not exist (gcd != 1, or invert of 0 / non-positive modulus). */
    CRYPTO_INVERSE_NOT_EXIST: "TIDE-TIDEJS-CRYPTO-INVERSE_NOT_EXIST",
    /** A low-level crypto primitive received a value of an unexpected JS type (e.g. `invert` expected a bigint). */
    CRYPTO_INVALID_BIGINT_INPUT: "TIDE-TIDEJS-CRYPTO-INVALID_BIGINT_INPUT",
    /** Hash-to-Point (RFC 9380 expand_message_xmd / i2osp) received an out-of-range input. */
    CRYPTO_HASH_TO_POINT_INVALID_INPUT: "TIDE-TIDEJS-CRYPTO-HASH_TO_POINT_INVALID_INPUT",

    // --- Signature -------------------------------------------------------
    /** Non-blind signature verification failed (e.g. Ed25519Scheme `verifyingFunc`). */
    SIG_VERIFY_FAILED: "TIDE-TIDEJS-SIG-VERIFY_FAILED",

    // --- Serialization helpers -----------------------------------------
    /** A numeric value cannot be represented in the requested width (e.g. > Int64 / > 255 byte). */
    SERIAL_LENGTH_OUT_OF_RANGE: "TIDE-TIDEJS-SERIAL-LENGTH_OUT_OF_RANGE",
    /** The supplied argument was not of the expected JS type (e.g. expected Uint8Array, got something else). */
    SERIAL_INVALID_TYPE: "TIDE-TIDEJS-SERIAL-INVALID_TYPE",
    /** A serialization helper found data already present where an empty slot was expected. */
    SERIAL_INDEX_OOB: "TIDE-TIDEJS-SERIAL-INDEX_OOB",
    /** A serialization write would have exceeded the destination buffer's capacity. */
    SERIAL_BUFFER_OVERFLOW: "TIDE-TIDEJS-SERIAL-BUFFER_OVERFLOW",
    /** A length-tagged input did not match the expected length (e.g. TIDE_KEY blob != 32 bytes). */
    SERIAL_INVALID_LENGTH: "TIDE-TIDEJS-SERIAL-INVALID_LENGTH",
    /** A header / magic value did not match the expected token (e.g. "tidexxxkey" prefix mismatch). */
    SERIAL_UNEXPECTED_HEADER: "TIDE-TIDEJS-SERIAL-UNEXPECTED_HEADER",
    /** A hex string failed regex validation. */
    SERIAL_INVALID_HEX: "TIDE-TIDEJS-SERIAL-INVALID_HEX",
    /** A base64 string failed validation or decoding. */
    SERIAL_INVALID_BASE64: "TIDE-TIDEJS-SERIAL-INVALID_BASE64",
    /** Two operand arrays had unequal lengths where equal lengths were required (e.g. XOR). */
    SERIAL_LENGTH_MISMATCH: "TIDE-TIDEJS-SERIAL-LENGTH_MISMATCH",

    // --- Model validation ----------------------------------------------
    /** A model field (Doken/AuthRequest/TideKey) failed a shape/type guard during construction or parsing. */
    MODEL_INVALID_FIELD: "TIDE-TIDEJS-MODEL-INVALID_FIELD",
    /** A model header value (e.g. Doken `alg`/`typ`) did not match the expected value. */
    MODEL_UNEXPECTED_HEADER: "TIDE-TIDEJS-MODEL-UNEXPECTED_HEADER",
    /** A model expected a specific shape (e.g. Doken = 3 parts) and the input did not conform. */
    MODEL_INVALID_SHAPE: "TIDE-TIDEJS-MODEL-INVALID_SHAPE",
    /** A TideKey was constructed/derived from a component that does not satisfy the required interface. */
    MODEL_INVALID_KEY: "TIDE-TIDEJS-MODEL-INVALID_KEY",
    /** A model field's value was not in the allowed range (e.g. VRK expiry too close to now). */
    MODEL_VALUE_OUT_OF_RANGE: "TIDE-TIDEJS-MODEL-VALUE_OUT_OF_RANGE",
    /** ModelRegistry could not resolve a sign-request name:version to a builder (unknown model id). */
    MODEL_UNKNOWN_MODEL: "TIDE-TIDEJS-MODEL-UNKNOWN_MODEL",
    /** A PolicyParameters entry carries an unrecognised type tag (e.g. not str/num/bnum/bln/byt). */
    MODEL_UNKNOWN_PARAM_TYPE: "TIDE-TIDEJS-MODEL-UNKNOWN_PARAM_TYPE",
    /** `Policy.getParameter` was asked for a parameter key that does not exist on the policy. */
    MODEL_PARAM_NOT_FOUND: "TIDE-TIDEJS-MODEL-PARAM_NOT_FOUND",
    /** A developer-only invariant was violated inside a Policy version handler (should be unreachable in production). */
    MODEL_DEV_ERROR: "TIDE-TIDEJS-MODEL-DEV_ERROR",
    /** A request (e.g. BaseTideRequest) was used before a required field (authorizer / authorization / cert) had been added. */
    MODEL_REQUEST_NOT_INITIALIZED: "TIDE-TIDEJS-MODEL-REQUEST_NOT_INITIALIZED",
    /** A serialized model header carried an unsupported version tag (Policy / SerializedField). */
    MODEL_VERSION_MISMATCH: "TIDE-TIDEJS-MODEL-VERSION_MISMATCH",

    // --- TideMemory guards ---------------------------------------------
    /** Caller supplied a negative index to a TideMemory helper. */
    MEM_NEGATIVE_INDEX: "TIDE-TIDEJS-MEM-NEGATIVE_INDEX",
    /** Caller attempted to overwrite the zero-index slot via WriteValue (must use Create). */
    MEM_INDEX_ZERO_RESERVED: "TIDE-TIDEJS-MEM-INDEX_ZERO_RESERVED",
    /** TideMemory write would exceed the destination buffer's capacity. */
    MEM_BUFFER_OVERFLOW: "TIDE-TIDEJS-MEM-BUFFER_OVERFLOW",
    /** TideMemory read sought past the encoded segments of the buffer. */
    MEM_INDEX_OUT_OF_RANGE: "TIDE-TIDEJS-MEM-INDEX_OUT_OF_RANGE",
    /** TideMemory buffer is too small to hold even the version header. */
    MEM_INSUFFICIENT_DATA: "TIDE-TIDEJS-MEM-INSUFFICIENT_DATA",
    /** TideMemory write attempted at an index already populated with data. */
    MEM_INDEX_ALREADY_WRITTEN: "TIDE-TIDEJS-MEM-INDEX_ALREADY_WRITTEN",
} as const);

export type TideJsErrorCode = typeof TideJsErrorCodes[keyof typeof TideJsErrorCodes];
