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

import { TideError } from "../Errors/TideError";
import { TideJsErrorCodes } from "../Errors/codes";
import { RecentRequestsBuffer, RecentRequestEntry } from "./RecentRequestsBuffer";

/**
 * Derive a path-only endpoint from a full URL, falling back to the raw URL
 * if URL parsing fails (e.g. relative URL with no base, or malformed input).
 * Centralised here so every {@link RecentRequestsBuffer} entry is shaped the
 * same way.
 */
function _endpointFromUrl(url: string): string {
    try {
        return new URL(url).pathname;
    } catch {
        return url;
    }
}

/**
 * Push a {@link RecentRequestEntry} for a request that has just resolved or
 * rejected. Centralised so the per-method instrumentation in `_get`/`_post`/
 * `_postJSON`/`_put` is small and consistent.
 *
 * `err` is examined defensively (we don't `instanceof TideError` because
 * downstream bundlers can create cross-module instances): we check for the
 * structural shape of TideError just like {@link TideError.isTideError}.
 */
function _pushRecent(
    url: string,
    method: string,
    perfStart: number,
    success: boolean,
    response: Response | null,
    err: unknown,
): void {
    const durationMs = performance.now() - perfStart;
    let httpStatus: number | null = null;
    let code: string | null = null;
    if (success && response) {
        httpStatus = response.status;
        code = null;
    } else if (TideError.isTideError(err)) {
        httpStatus = (err as TideError).httpStatus ?? null;
        code = (err as TideError).code;
    } else {
        httpStatus = null;
        code = TideJsErrorCodes.NET_UNKNOWN;
    }
    const entry: RecentRequestEntry = {
        timestamp: new Date().toISOString(),
        url,
        endpoint: _endpointFromUrl(url),
        method,
        httpStatus,
        durationMs,
        code,
    };
    try {
        RecentRequestsBuffer.push(entry);
    } catch {
        /* never let buffer bookkeeping affect the actual request outcome */
    }
}

/**
 * RFC 7807 Problem Details envelope, with Tide-specific extensions.
 * See `agents/...` locked spec — this shape is the cross-project contract
 * between ORK / idp-extensions (producer) and tide-js (consumer).
 */
interface ProblemDetails {
    type?: string;
    title?: string;
    status?: number;
    detail?: string;
    instance?: string;
    code?: string;
    traceId?: string;
    source?: string;
    messageKey?: string | null;
    messageParams?: Record<string, unknown> | null;
}

export default class ClientBase {
    url: string;
    token: string;
    sessionKeyPrivateRaw: any;
    sessionKeyPublicEncoded: any;

    constructor(url: string) {
        this.url = url
    }

    _createFormData(form: Object): FormData {
        const formData = new FormData();

        Object.entries(form).forEach(([key, value]) => {
            if (Array.isArray(value)) {
                for (let i = 0; i < value.length; i++) {
                    formData.append(key + "[" + i + "]", value[i] as any)
                }
            }
            else
                formData.append(key, value as any)
        });

        return formData
    }

    /**
     * Distinguish AbortError causes:
     *  - if the caller supplied their own signal AND it is now aborted, classify as NET_ABORTED
     *  - otherwise we hit our internal `setTimeout` -> NET_TIMEOUT
     *  - everything else (TypeError from fetch, DNS, CORS, ...) -> NET_FETCH_FAILED
     *
     * `endpoint` + `method` are threaded through so the resulting TideError
     * carries the full URL of the failed call — this is what makes the error
     * debuggable in the browser console (you immediately see *which* ORK was
     * unreachable, not just "Network request failed").
     */
    private _classifyFetchError(
        e: unknown,
        callerSignal: AbortSignal | null,
        source: string,
        endpoint: string,
        method: string,
    ): TideError {
        const url = this.url + endpoint;
        const isAbort =
            (typeof DOMException !== "undefined" && e instanceof DOMException && e.name === "AbortError")
            || (e instanceof Error && e.name === "AbortError");

        if (isAbort) {
            if (callerSignal && callerSignal.aborted) {
                return new TideError({
                    code: TideJsErrorCodes.NET_ABORTED,
                    displayMessage: "Network request was aborted by the caller",
                    source,
                    url,
                    endpoint,
                    method,
                    cause: e,
                });
            }
            return new TideError({
                code: TideJsErrorCodes.NET_TIMEOUT,
                displayMessage: "Network request timed out",
                source,
                url,
                endpoint,
                method,
                cause: e,
            });
        }

        return new TideError({
            code: TideJsErrorCodes.NET_FETCH_FAILED,
            displayMessage: "Network request failed",
            source,
            url,
            endpoint,
            method,
            cause: e,
        });
    }

    async _get(endpoint: string, timeout: number = 20000, signal: AbortSignal = null): Promise<Response> {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        const fullUrl = this.url + endpoint;
        const perfStart = performance.now();

        let response;
        try {
            response = await fetch(fullUrl, {
                method: 'GET',
                signal: signal ?? controller.signal
            });
            clearTimeout(id);
        } catch (e) {
            clearTimeout(id);
            const tideErr = this._classifyFetchError(e, signal, "Clients/ClientBase.ts:_get", endpoint, "GET");
            _pushRecent(fullUrl, "GET", perfStart, false, null, tideErr);
            throw tideErr;
        }
        if (!response.ok) {
            const tideErr = new TideError({
                code: TideJsErrorCodes.NET_NON_OK_STATUS,
                displayMessage: `Request to ${endpoint} returned HTTP ${response.status}`,
                httpStatus: response.status,
                source: "Clients/ClientBase.ts:_get",
                url: fullUrl,
                endpoint,
                method: "GET",
            });
            _pushRecent(fullUrl, "GET", perfStart, false, response, tideErr);
            throw tideErr;
        }
        _pushRecent(fullUrl, "GET", perfStart, true, response, null);
        return response;
    }

    /**
    * Silent get, makes a returns a response without handling response errors.
    */
    async _getSilent(endpoint: string, timeout: number = 20000, signal: AbortSignal = null): Promise<Response> {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        let response;
        try {
            response = await fetch(this.url + endpoint, {
                method: 'GET',
                signal: signal ?? controller.signal
            });
            clearTimeout(id);
        } catch (e) {
            clearTimeout(id);
            throw this._classifyFetchError(e, signal, "Clients/ClientBase.ts:_getSilent", endpoint, "GET");
        }
        if (!response.ok) {
            throw new TideError({
                code: TideJsErrorCodes.NET_NON_OK_STATUS,
                displayMessage: `Request to ${endpoint} returned HTTP ${response.status}`,
                httpStatus: response.status,
                source: "Clients/ClientBase.ts:_getSilent",
                url: this.url + endpoint,
                endpoint,
                method: "GET",
            });
        }
        return response;
    }

    async _post(endpoint: string, data: FormData, timeout: number = 20000): Promise<Response> {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        const fullUrl = this.url + endpoint;
        const perfStart = performance.now();

        if (this.token) data.append("token", this.token);

        let response;
        try {
            response = await fetch(fullUrl, {
                method: 'POST',
                body: data,
                signal: controller.signal
            });
            clearTimeout(id);
        } catch (e) {
            clearTimeout(id);
            // `_post` does not accept a caller signal — abort can only come
            // from our own timeout controller.
            const tideErr = this._classifyFetchError(e, null, "Clients/ClientBase.ts:_post", endpoint, "POST");
            _pushRecent(fullUrl, "POST", perfStart, false, null, tideErr);
            throw tideErr;
        }
        // Do NOT throw NET_NON_OK_STATUS here — for the voucher slice,
        // ORK now returns 4xx/5xx with `application/problem+json`, and
        // callers always pipe the response through `_handleError`, which
        // parses Problem Details and constructs a richer TideError. Throw
        // generically here would lose that information.
        // From `_post`'s POV the request "succeeded" the moment the server
        // produced any response (including 4xx/5xx) — we record the actual
        // status; the downstream `_handleError` will not push another entry
        // (it does not perform fetch, only parses the body), so this entry
        // is the authoritative record of the request.
        _pushRecent(fullUrl, "POST", perfStart, true, response, null);
        return response;
    }

    async _put(endpoint: string, data: FormData): Promise<Response> {
        const fullUrl = this.url + endpoint;
        const perfStart = performance.now();
        let response: Response;
        try {
            response = await fetch(fullUrl, {
                method: 'PUT',
                body: data
            });
        } catch (e) {
            // No timeout/abort plumbing on `_put` historically; tag unknown
            // failures as NET_FETCH_FAILED for the buffer.
            const tideErr = TideError.isTideError(e)
                ? (e as TideError)
                : new TideError({
                    code: TideJsErrorCodes.NET_FETCH_FAILED,
                    displayMessage: "Network request failed",
                    source: "Clients/ClientBase.ts:_put",
                    url: fullUrl,
                    endpoint,
                    method: "PUT",
                    cause: e,
                });
            _pushRecent(fullUrl, "PUT", perfStart, false, null, tideErr);
            throw tideErr;
        }
        _pushRecent(fullUrl, "PUT", perfStart, true, response, null);
        return response;
    }

    async _postJSON(endpoint: string, data: Object): Promise<Response> {
        const fullUrl = this.url + endpoint;
        const perfStart = performance.now();
        let response: Response;
        try {
            response = await fetch(fullUrl, {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });
        } catch (e) {
            const tideErr = TideError.isTideError(e)
                ? (e as TideError)
                : new TideError({
                    code: TideJsErrorCodes.NET_FETCH_FAILED,
                    displayMessage: "Network request failed",
                    source: "Clients/ClientBase.ts:_postJSON",
                    url: fullUrl,
                    endpoint,
                    method: "POST",
                    cause: e,
                });
            _pushRecent(fullUrl, "POST", perfStart, false, null, tideErr);
            throw tideErr;
        }
        _pushRecent(fullUrl, "POST", perfStart, true, response, null);
        return response;
    }

    /**
     * Post silent returns the response without handling response errors.
     */
    async _postSilent(endpoint: string, data: FormData, timeout: number = 20000): Promise<Response> {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        let response;
        try {
            response = await fetch(this.url + endpoint, {
                method: 'POST',
                body: data,
                signal: controller.signal
            });
            clearTimeout(id);
        } catch (e) {
            clearTimeout(id);
            throw this._classifyFetchError(e, null, "Clients/ClientBase.ts:_postSilent", endpoint, "POST");
        }
        return response;
    }

    /**
     * Convert a server response into either:
     *  - a success body (`text/plain`, voucher path, 2xx)
     *  - a thrown {@link TideError} (any error path)
     *
     * Branches in order of preference:
     *   1. `application/problem+json` (4xx/5xx) -> parse Problem Details, pass-through `code`/`traceId`/`type`/`detail`.
     *   2. Legacy `--FAILED--:` envelope on 200 -> wrap as `PARSE_UNKNOWN_FORMAT`, console.warn the upgrade hint.
     *   3. `!response.ok` with neither match -> `NET_NON_OK_STATUS`.
     *   4. Otherwise return the raw body text.
     *
     * The historical `throwError` parameter is preserved for API compatibility
     * but is now a no-op: we ALWAYS throw on error (and return body on success).
     * The previous mixed throw/reject behaviour was bug-prone — see locked spec.
     *
     * @param response The fetch Response.
     * @param functionName Name of the calling client method (for error source).
     * @param _throwError Deprecated, retained for ABI compatibility. Errors are always thrown.
     */
    async _handleError(response: Response, functionName: string = "", _throwError: boolean = false): Promise<string> {
        const contentType = response.headers.get("content-type") ?? "";
        const source = `Clients/ClientBase.ts:_handleError(${functionName})`;
        // `response.url` is the final URL (post-redirect). We use it as a
        // best-effort source for the debug fields; `_handleError` doesn't
        // know the original endpoint string, so we derive endpoint from the
        // URL path.
        const url = response.url || undefined;
        let endpoint: string | undefined;
        if (url) {
            try { endpoint = new URL(url).pathname; } catch { /* ignore */ }
        }

        // ---- (1) Problem Details (RFC 7807 + Tide extensions) -------------
        if (contentType.toLowerCase().includes("application/problem+json")) {
            const raw = await response.text();
            let problem: ProblemDetails;
            try {
                problem = JSON.parse(raw) as ProblemDetails;
            } catch (parseErr) {
                throw new TideError({
                    code: TideJsErrorCodes.PARSE_PROBLEM_JSON_INVALID,
                    displayMessage: "Server returned application/problem+json but the body did not parse",
                    httpStatus: response.status,
                    source,
                    url,
                    endpoint,
                    cause: parseErr,
                });
            }

            if (!problem || typeof problem !== "object" || typeof problem.code !== "string") {
                throw new TideError({
                    code: TideJsErrorCodes.PARSE_PROBLEM_JSON_INVALID,
                    displayMessage: "Server returned application/problem+json without a `code` field",
                    httpStatus: response.status,
                    source,
                    url,
                    endpoint,
                    problemType: problem?.type,
                    cause: raw,
                });
            }

            // Pass-through. The upstream `code` (e.g. `TIDE-ORK-SIG-VERIFY_FAILED`)
            // is preserved verbatim — keycloak-IGA's `getTideErrorInfo` expects
            // to see the originating code, not a tide-js wrapper code.
            throw new TideError({
                code: problem.code,
                displayMessage: problem.detail ?? problem.title ?? "Upstream error",
                messageKey: problem.messageKey ?? null,
                messageParams: problem.messageParams ?? null,
                traceId: problem.traceId,
                source: problem.source,
                httpStatus: problem.status ?? response.status,
                problemType: problem.type,
                url,
                endpoint,
            });
        }

        const responseData = await response.text();

        // ---- (2) Legacy `--FAILED--:` envelope on a 200 ------------------
        if (responseData.split(":")[0] === "--FAILED--") {
            const legacyDetail = responseData.split(":").slice(1).join(":");
            console.error(responseData);
            console.warn(
                `legacy --FAILED-- envelope from ${response.url || this.url} — server should be upgraded to application/problem+json`
            );
            throw new TideError({
                code: TideJsErrorCodes.PARSE_UNKNOWN_FORMAT,
                displayMessage: legacyDetail || "Legacy --FAILED-- envelope received",
                httpStatus: response.status,
                source,
                url,
                endpoint,
                cause: responseData,
            });
        }

        // ---- (3) Non-ok with no recognised envelope ----------------------
        if (!response.ok) {
            throw new TideError({
                code: TideJsErrorCodes.NET_NON_OK_STATUS,
                displayMessage: `Request returned HTTP ${response.status}`,
                httpStatus: response.status,
                source,
                url,
                endpoint,
                cause: responseData,
            });
        }

        // ---- (4) Success -------------------------------------------------
        return responseData;
    }

    async _handleErrorSimulator(response: Response): Promise<string> {
        const responseData = await response.text();
        if (!response.ok) {
            throw new TideError({
                code: TideJsErrorCodes.NET_NON_OK_STATUS,
                displayMessage: responseData || `Request returned HTTP ${response.status}`,
                httpStatus: response.status,
                source: "Clients/ClientBase.ts:_handleErrorSimulator",
                cause: responseData,
            });
        }
        return responseData;
    }

    AddBearerAuthorization(sessionKeyPrivate: Uint8Array, sessionKeyPublicEncoded: string, token: string) {
        this.sessionKeyPrivateRaw = sessionKeyPrivate;
        this.sessionKeyPublicEncoded = sessionKeyPublicEncoded;
        this.token = token;
        return this;
    }
}
