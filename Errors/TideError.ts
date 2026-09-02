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
 * One element of {@link TideErrorInit.details} — used by aggregate errors
 * (e.g. "could not reach enough ORKs") to carry the per-attempt failures.
 * Kept structural (not a class) so callers can spread/serialise freely.
 */
export interface TideErrorDetail {
    /** Per-attempt URL, if known (e.g. `http://hostgateway:1002/Authentication/Auth/Convert?uid=...`). */
    url?: string;
    /** Per-attempt endpoint path, if known. */
    endpoint?: string;
    /** Per-attempt HTTP method, if known. */
    method?: string;
    /** Canonical error code of the underlying failure. */
    code?: string;
    /** UI-safe message of the underlying failure. */
    displayMessage?: string;
    /** Underlying error object (preserved for stack inspection in the console). */
    cause?: unknown;
}

/**
 * Initialiser shape for {@link TideError}. Always passed as a single object
 * so call-sites are self-documenting and field order can never drift.
 */
export interface TideErrorInit {
    /**
     * Canonical error code. Either a {@link TideJsErrorCodes} value, or — for
     * pass-through of upstream Problem Details — the upstream code verbatim
     * (e.g. `"TIDE-ORK-SIG-VERIFY_FAILED"`).
     */
    code: string;
    /** Human-readable, UI-safe message. For upstream errors this comes from `problem.detail`. */
    displayMessage: string;
    /** Optional i18n message key, mirroring the upstream Problem Details `messageKey`. */
    messageKey?: string | null;
    /** Optional i18n message params, mirroring the upstream Problem Details `messageParams`. */
    messageParams?: Record<string, unknown> | null;
    /** W3C trace-context `traceparent` value, propagated verbatim from upstream. */
    traceId?: string;
    /** Server-side source location, e.g. `"Ork/Voucher/Verifier.cs:142"`, or the tide-js call-site for locally-originated errors. */
    source?: string;
    /** HTTP status code if the error originated from an HTTP response. */
    httpStatus?: number;
    /** The Problem Details `type` URI (e.g. `"urn:tide:errors:TIDE-ORK-SIG-VERIFY_FAILED"`). */
    problemType?: string;
    /**
     * Full request URL that this error originated from, when knowable at
     * throw-time. Populated for client-emitted network errors so a dev
     * inspecting the console immediately sees which ORK / endpoint failed.
     * Server-emitted Problem Details responses leave this `undefined`.
     */
    url?: string;
    /** Path portion of {@link url} alone, e.g. `/Authentication/Auth/Convert`. */
    endpoint?: string;
    /** HTTP method of the failed request, e.g. `"GET"` / `"POST"`. */
    method?: string;
    /**
     * For aggregate errors (e.g. "not enough ORKs reached threshold"): the
     * underlying per-attempt failures. Each entry summarises one failed call.
     */
    details?: TideErrorDetail[];
    /** Underlying cause (network error, JSON parse error, raw response text, ...). */
    cause?: unknown;
}

/**
 * Single, structured error type thrown across tide-js.
 *
 * Consumers (notably keycloak-IGA's `getTideErrorInfo`) introspect instances
 * via {@link TideError.isTideError} and read the listed fields directly — so
 * the field names here form a cross-project public contract and MUST NOT be
 * renamed without coordination.
 */
export class TideError extends Error {
    /** Canonical error code (see {@link TideErrorInit.code}). */
    public readonly code: string;
    /** UI-safe message (see {@link TideErrorInit.displayMessage}). */
    public readonly displayMessage: string;
    public readonly messageKey?: string | null;
    public readonly messageParams?: Record<string, unknown> | null;
    public readonly traceId?: string;
    public readonly source?: string;
    public readonly httpStatus?: number;
    public readonly problemType?: string;
    /** Full request URL when knowable (client-emitted network errors only). */
    public readonly url?: string;
    /** Endpoint path portion of {@link url}. */
    public readonly endpoint?: string;
    /** HTTP method of the failed request. */
    public readonly method?: string;
    /** Per-attempt underlying failures, populated on aggregate errors only. */
    public readonly details?: TideErrorDetail[];

    constructor(init: TideErrorInit) {
        // `Error.cause` is only honoured by ES2022+; we pass it via the options
        // bag so engines that support it set it for us, and we re-assign below
        // defensively for engines that drop it silently.
        super(init.displayMessage, init.cause !== undefined ? { cause: init.cause } : undefined);

        // Required for downlevel emit (`target` < ES2022) where `Error`
        // subclassing otherwise produces a plain Error at runtime.
        Object.setPrototypeOf(this, TideError.prototype);

        this.name = "TideError";
        this.code = init.code;
        this.displayMessage = init.displayMessage;
        this.messageKey = init.messageKey ?? null;
        this.messageParams = init.messageParams ?? null;
        this.traceId = init.traceId;
        this.source = init.source;
        this.httpStatus = init.httpStatus;
        this.problemType = init.problemType;
        this.url = init.url;
        this.endpoint = init.endpoint;
        this.method = init.method;
        this.details = init.details;

        // Defensive cause assignment (no-op on engines that already set it).
        if (init.cause !== undefined && (this as any).cause === undefined) {
            try {
                Object.defineProperty(this, "cause", {
                    value: init.cause,
                    writable: true,
                    configurable: true,
                });
            } catch {
                /* ignore — read-only environments will already have `cause` */
            }
        }
    }

    /**
     * Developer-facing string form. Surfaces the most-useful debugging fields
     * (`method`, `url`, `source`, `httpStatus`, `cause`, and a summary of
     * `details` for aggregate errors) at the top of the printed error so a
     * dev opening the browser console sees them immediately instead of
     * having to expand `cause` or scroll through stack frames.
     *
     * Format example:
     *   TideError[TIDE-TIDEJS-NET-FETCH_FAILED]: Network request failed
     *     method:   POST
     *     url:      http://hostgateway:1002/Authentication/Auth/Convert?uid=...
     *     source:   Clients/ClientBase.ts:_post
     *     cause:    TypeError: Failed to fetch
     */
    override toString(): string {
        const lines: string[] = [`TideError[${this.code}]: ${this.displayMessage}`];
        const pad = (label: string) => (label + ":").padEnd(10, " ");
        if (this.method) lines.push(`  ${pad("method")}${this.method}`);
        if (this.url) lines.push(`  ${pad("url")}${this.url}`);
        else if (this.endpoint) lines.push(`  ${pad("endpoint")}${this.endpoint}`);
        if (this.httpStatus !== undefined) lines.push(`  ${pad("status")}${this.httpStatus}`);
        if (this.source) lines.push(`  ${pad("source")}${this.source}`);
        if (this.traceId) lines.push(`  ${pad("traceId")}${this.traceId}`);
        if (this.details && this.details.length > 0) {
            lines.push(`  ${pad("details")}${this.details.length} underlying failure(s):`);
            for (const d of this.details) {
                const tag = d.url ?? d.endpoint ?? "<unknown>";
                const codePart = d.code ? ` [${d.code}]` : "";
                const msgPart = d.displayMessage ? ` ${d.displayMessage}` : "";
                lines.push(`    - ${tag}${codePart}${msgPart}`);
            }
        }
        const causeVal = (this as any).cause;
        if (causeVal !== undefined && causeVal !== null) {
            const causeStr = causeVal instanceof Error
                ? `${causeVal.name}: ${causeVal.message}`
                : String(causeVal);
            lines.push(`  ${pad("cause")}${causeStr}`);
        }
        return lines.join("\n");
    }

    /**
     * Structural type guard. Used by external consumers (keycloak-IGA) that
     * cannot rely on `instanceof` across module/bundling boundaries.
     */
    static isTideError(e: unknown): e is TideError {
        if (e instanceof TideError) return true;
        if (e === null || typeof e !== "object") return false;
        const candidate = e as { name?: unknown; code?: unknown; displayMessage?: unknown };
        return candidate.name === "TideError"
            && typeof candidate.code === "string"
            && typeof candidate.displayMessage === "string";
    }
}
