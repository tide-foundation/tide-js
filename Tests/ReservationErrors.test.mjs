// Node unit tests for the reservation-error-surfacing changes:
//   1. Case-tolerant ProblemDetails parsing (Clients/ClientBase.ts)
//   2. `_get` problem+json pass-through on non-ok statuses
//   3. Opt-in unanimous-code promotion in PromiseRace (Tools/Utils.ts)
//
// Runs against the compiled `dist/` output (see the `test` script in
// package.json — `tsc` is run first). Browser APIs are not required: the
// code paths under test only use `fetch` (stubbed here), `Response`,
// `Headers` and `performance`, all available in Node >= 18.
//
// Run: npm test
import { test } from "node:test";
import assert from "node:assert/strict";

import ClientBase from "../dist/Clients/ClientBase.js";
import { WaitForNumberofORKs } from "../dist/Tools/Utils.js";
import { TideError } from "../dist/Errors/TideError.js";
import { TideJsErrorCodes } from "../dist/Errors/codes.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const RESERVED_CODE = "TIDE-ORK-KEYGEN-USERNAME_RESERVED";
const RESERVED_KEY = "error.tide.ork.keygen.username_reserved";

/** The ork-side wire form: PascalCase envelope, string MessageParams values. */
function pascalCaseBody(expirySeconds = "1765500000") {
    return JSON.stringify({
        Type: `urn:tide:errors:${RESERVED_CODE}`,
        Title: "Username reserved",
        Status: 409,
        Detail: "This username was recently reserved by another sign-up attempt",
        Code: RESERVED_CODE,
        TraceId: "00-aaaabbbbccccddddeeeeffff00001111-2222333344445555-01",
        Source: "Ork/KeyGeneration/Reservation.cs:88",
        MessageKey: RESERVED_KEY,
        MessageParams: { minutes: "10", expirySeconds },
    });
}

/** Legacy / RFC 7807 lowercase form (must remain accepted for compat). */
function lowercaseBody() {
    return JSON.stringify({
        type: `urn:tide:errors:${RESERVED_CODE}`,
        title: "Username reserved",
        status: 409,
        detail: "This username was recently reserved by another sign-up attempt",
        code: RESERVED_CODE,
        traceId: "00-aaaabbbbccccddddeeeeffff00001111-2222333344445555-01",
        source: "Ork/KeyGeneration/Reservation.cs:88",
        messageKey: RESERVED_KEY,
        messageParams: { minutes: "10", expirySeconds: "1765500000" },
    });
}

function problemResponse(body, status = 409) {
    return new Response(body, {
        status,
        headers: { "content-type": "application/problem+json" },
    });
}

async function expectThrow(fn) {
    try {
        await fn();
    } catch (e) {
        return e;
    }
    assert.fail("expected the call to throw, but it resolved");
}

function assertStructuredReservedError(err) {
    assert.equal(err.name, "TideError", "name invariant must hold");
    assert.ok(TideError.isTideError(err));
    assert.equal(err.code, RESERVED_CODE);
    assert.equal(err.messageKey, RESERVED_KEY, "messageKey must pass through verbatim");
    assert.deepEqual(err.messageParams, { minutes: "10", expirySeconds: "1765500000" });
    assert.equal(err.httpStatus, 409);
    assert.equal(err.problemType, `urn:tide:errors:${RESERVED_CODE}`);
    assert.equal(err.traceId, "00-aaaabbbbccccddddeeeeffff00001111-2222333344445555-01");
}

// ---------------------------------------------------------------------------
// 1. ProblemDetails parsing (_handleError)
// ---------------------------------------------------------------------------

test("_handleError parses PascalCase ProblemDetails (canonical ork wire form)", async () => {
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() =>
        client._handleError(problemResponse(pascalCaseBody()), "Find Reservers"));
    assertStructuredReservedError(err);
});

test("_handleError still parses lowercase ProblemDetails (compat)", async () => {
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() =>
        client._handleError(problemResponse(lowercaseBody()), "Find Reservers"));
    assertStructuredReservedError(err);
});

test("_handleError: non-JSON problem+json body falls back to PARSE_PROBLEM_JSON_INVALID", async () => {
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() =>
        client._handleError(problemResponse("<<< not json >>>"), "Find Reservers"));
    assert.equal(err.name, "TideError");
    assert.equal(err.code, TideJsErrorCodes.PARSE_PROBLEM_JSON_INVALID);
});

test("_handleError: problem+json object without code/Code falls back to PARSE_PROBLEM_JSON_INVALID", async () => {
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() =>
        client._handleError(problemResponse(JSON.stringify({ Title: "nope", Status: 409 })), "x"));
    assert.equal(err.code, TideJsErrorCodes.PARSE_PROBLEM_JSON_INVALID);
});

// ---------------------------------------------------------------------------
// 2. _get problem+json pass-through
// ---------------------------------------------------------------------------

test("_get: 409 problem+json throws the structured pass-through error", async (t) => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = async () => problemResponse(pascalCaseBody());
    t.after(() => { globalThis.fetch = realFetch; });

    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() =>
        client._get("/Network/Authentication/Users/GetReservers/uid123"));
    assertStructuredReservedError(err);
    assert.equal(err.method, "GET");
    assert.equal(err.url, "http://ork.example/Network/Authentication/Users/GetReservers/uid123");
});

test("_get: non-problem+json 409 still throws NET_NON_OK_STATUS", async (t) => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = async () =>
        new Response("Conflict", { status: 409, headers: { "content-type": "text/plain" } });
    t.after(() => { globalThis.fetch = realFetch; });

    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() => client._get("/some/endpoint"));
    assert.equal(err.code, TideJsErrorCodes.NET_NON_OK_STATUS);
    assert.equal(err.httpStatus, 409);
});

test("_getSilent: 409 problem+json throws the structured pass-through error", async (t) => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = async () => problemResponse(pascalCaseBody());
    t.after(() => { globalThis.fetch = realFetch; });

    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() => client._getSilent("/x"));
    assertStructuredReservedError(err);
});

// ---------------------------------------------------------------------------
// 3. PromiseRace unanimous-code promotion (via WaitForNumberofORKs)
// ---------------------------------------------------------------------------

function reservedFailure(expirySeconds) {
    return new TideError({
        code: RESERVED_CODE,
        displayMessage: "This username was recently reserved by another sign-up attempt",
        messageKey: RESERVED_KEY,
        messageParams: { minutes: "10", expirySeconds },
        httpStatus: 409,
        problemType: `urn:tide:errors:${RESERVED_CODE}`,
        traceId: "00-aaaabbbbccccddddeeeeffff00001111-2222333344445555-01",
        url: "http://ork.example/Network/Authentication/Users/GetReservers/uid123",
        endpoint: "/Network/Authentication/Users/GetReservers/uid123",
        method: "GET",
    });
}

function transportFailure() {
    return new TideError({
        code: TideJsErrorCodes.NET_TIMEOUT,
        displayMessage: "Network request timed out",
        source: "Clients/ClientBase.ts:_get",
    });
}

/** Drive WaitForNumberofORKs into the failure path with the given rejections. */
function raceWith(failures, opts) {
    const promises = failures.map(f => Promise.reject(f));
    // customTimeout=50ms so the test does not wait the default 8s.
    return WaitForNumberofORKs([], promises, "CMK", failures.length, null, null, 50, null, opts);
}

test("promotion: unanimous reserved code is promoted, representative = largest expirySeconds", async () => {
    const failures = [reservedFailure("100"), reservedFailure("300"), reservedFailure("200")];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));

    assert.equal(err.name, "TideError", "promoted error must keep the TideError name invariant");
    assert.equal(err.code, RESERVED_CODE);
    assert.equal(err.messageKey, RESERVED_KEY);
    assert.deepEqual(err.messageParams, { minutes: "10", expirySeconds: "300" },
        "representative must be the failure with the largest numeric expirySeconds");
    assert.equal(err.httpStatus, 409);
    assert.equal(err.traceId, "00-aaaabbbbccccddddeeeeffff00001111-2222333344445555-01");
    assert.match(err.source, /promoted: 3 identical per-ORK failures/);
    assert.equal(err.details.length, 3, "aggregate details must be preserved");
    assert.equal(err.cause, failures[1], "cause must be the representative failure");
});

test("promotion: absent/NaN expirySeconds falls back to first failure", async () => {
    const noExpiry = new TideError({
        code: RESERVED_CODE,
        displayMessage: "reserved (no params)",
        messageKey: RESERVED_KEY,
    });
    const alsoNoExpiry = new TideError({
        code: RESERVED_CODE,
        displayMessage: "reserved (NaN params)",
        messageKey: RESERVED_KEY,
        messageParams: { expirySeconds: "not-a-number" },
    });
    const err = await expectThrow(() => raceWith([noExpiry, alsoNoExpiry], { promoteUnanimousCodes: true }));
    assert.equal(err.code, RESERVED_CODE);
    assert.equal(err.cause, noExpiry);
});

test("promotion: mixed codes stay generic NET_THRESHOLD_FAILURE", async () => {
    const failures = [reservedFailure("100"), transportFailure()];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));
    assert.equal(err.code, TideJsErrorCodes.NET_THRESHOLD_FAILURE);
    assert.equal(err.details.length, 2);
});

test("promotion: unanimous TIDE-TIDEJS-* transport codes stay generic", async () => {
    const failures = [transportFailure(), transportFailure(), transportFailure()];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));
    assert.equal(err.code, TideJsErrorCodes.NET_THRESHOLD_FAILURE);
});

test("promotion: flag off (default) keeps generic NET_THRESHOLD_FAILURE even when unanimous", async () => {
    const failures = [reservedFailure("100"), reservedFailure("200")];
    const err = await expectThrow(() => raceWith(failures));
    assert.equal(err.code, TideJsErrorCodes.NET_THRESHOLD_FAILURE);
    // The reserved code must still be reachable via details[].
    assert.ok(err.details.every(d => d.code === RESERVED_CODE));
});

test("promotion: explicit false keeps generic NET_THRESHOLD_FAILURE", async () => {
    const failures = [reservedFailure("100"), reservedFailure("200")];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: false }));
    assert.equal(err.code, TideJsErrorCodes.NET_THRESHOLD_FAILURE);
});
