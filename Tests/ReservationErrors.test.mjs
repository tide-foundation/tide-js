// Node unit tests for the reservation-error-surfacing changes:
//   1. Case-tolerant ProblemDetails parsing (Clients/ClientBase.ts)
//   2. `_get` problem+json pass-through on non-ok statuses
//   3. Opt-in unanimous-code promotion in PromiseRace (Tools/Utils.ts)
//   4. Phase 4 security hardening:
//      - true-unanimity gate (partial failure sets never promote)
//      - median representative selection (honest-majority, non-finite never wins)
//      - ProblemDetails field validation (drop/truncate, never throw)
//      - promoted-messageKey namespace guard (error(s).tide.* only)
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
// 3. ProblemDetails field validation (drop/truncate, never throw)
// ---------------------------------------------------------------------------

test("validation: 1MB PascalCase Detail is truncated to 2048, no throw", async () => {
    const huge = "A".repeat(1024 * 1024);
    const body = JSON.stringify({
        Status: 409,
        Detail: huge,
        Code: RESERVED_CODE,
        MessageKey: RESERVED_KEY,
        MessageParams: { minutes: "3" },
    });
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() => client._handleError(problemResponse(body), "x"));
    assert.equal(err.code, RESERVED_CODE);
    assert.equal(err.displayMessage.length, 2048, "detail must be truncated to 2048 chars");
});

test("validation: __proto__ key in messageParams is dropped without prototype pollution", async () => {
    // Raw string so JSON.parse (not an object literal) produces the own
    // `__proto__` data property, exactly like a hostile wire body would.
    const body = `{"Status":409,"Code":"${RESERVED_CODE}","Detail":"d",`
        + `"MessageParams":{"__proto__":{"polluted":"yes"},"constructor":"x","minutes":"3"}}`;
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() => client._handleError(problemResponse(body), "x"));
    assert.equal(err.code, RESERVED_CODE);
    assert.deepEqual(err.messageParams, { minutes: "3" },
        "__proto__/constructor keys must be dropped");
    assert.ok(!Object.prototype.hasOwnProperty.call(err.messageParams, "__proto__"));
    assert.equal({}.polluted, undefined, "Object.prototype must not be polluted");
});

test("validation: messageParams capped at 16 keys, values String()-coerced and truncated to 256", async () => {
    const params = {};
    for (let i = 0; i < 50; i++) params[`k${i}`] = i < 1 ? "B".repeat(5000) : 42;
    const body = JSON.stringify({ Status: 409, Code: RESERVED_CODE, Detail: "d", MessageParams: params });
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() => client._handleError(problemResponse(body), "x"));
    assert.equal(err.code, RESERVED_CODE);
    assert.equal(Object.keys(err.messageParams).length, 16, "at most 16 keys kept");
    assert.equal(err.messageParams.k0.length, 256, "values truncated to 256");
    assert.equal(err.messageParams.k1, "42", "values coerced via String()");
});

test("validation: messageParams keys outside ^[A-Za-z0-9_]{1,64}$ are dropped", async () => {
    const body = JSON.stringify({
        Status: 409, Code: RESERVED_CODE, Detail: "d",
        MessageParams: { "minutes": "3", "bad key!": "x", ["L".repeat(65)]: "y" },
    });
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() => client._handleError(problemResponse(body), "x"));
    assert.deepEqual(err.messageParams, { minutes: "3" });
});

test("validation: non-object / array messageParams degrades to null, no throw", async () => {
    const client = new ClientBase("http://ork.example");
    for (const bad of ['"a string"', "[1,2,3]", "12"]) {
        const body = `{"Status":409,"Code":"${RESERVED_CODE}","Detail":"d","MessageParams":${bad}}`;
        const err = await expectThrow(() => client._handleError(problemResponse(body), "x"));
        assert.equal(err.code, RESERVED_CODE);
        assert.equal(err.messageParams, null);
    }
});

test("validation: code failing the charset is DROPPED -> PARSE_PROBLEM_JSON_INVALID", async () => {
    const body = JSON.stringify({ Status: 409, Code: "TIDE CODE WITH SPACES <script>", Detail: "d" });
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() => client._handleError(problemResponse(body), "x"));
    assert.equal(err.code, TideJsErrorCodes.PARSE_PROBLEM_JSON_INVALID,
        "an invalid code must degrade to the existing no-code fallback, not throw");
});

test("validation: code longer than 256 chars is dropped -> PARSE_PROBLEM_JSON_INVALID", async () => {
    const body = JSON.stringify({ Status: 409, Code: "X".repeat(257), Detail: "d" });
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() => client._handleError(problemResponse(body), "x"));
    assert.equal(err.code, TideJsErrorCodes.PARSE_PROBLEM_JSON_INVALID);
});

test("validation: messageKey failing the charset is dropped; non-string envelope fields dropped; traceId truncated", async () => {
    const body = JSON.stringify({
        Status: 409,
        Code: RESERVED_CODE,
        Detail: { not: "a string" },        // dropped -> falls back to Title
        Title: "Username reserved",
        MessageKey: "error.tide.x y<z>",    // charset fail -> dropped
        TraceId: "T".repeat(1000),          // truncated to 256
        Source: 12345,                      // dropped
    });
    const client = new ClientBase("http://ork.example");
    const err = await expectThrow(() => client._handleError(problemResponse(body), "x"));
    assert.equal(err.code, RESERVED_CODE);
    assert.equal(err.messageKey, null);
    assert.equal(err.displayMessage, "Username reserved");
    assert.equal(err.traceId.length, 256);
    assert.equal(err.source, undefined);
});

// ---------------------------------------------------------------------------
// 4. PromiseRace unanimous-code promotion (via WaitForNumberofORKs)
// ---------------------------------------------------------------------------

function reservedFailure(minutes, extra = {}) {
    return new TideError({
        code: RESERVED_CODE,
        displayMessage: "This username was recently reserved by another sign-up attempt",
        messageKey: RESERVED_KEY,
        messageParams: minutes === undefined ? null : { minutes },
        httpStatus: 409,
        problemType: `urn:tide:errors:${RESERVED_CODE}`,
        traceId: "00-aaaabbbbccccddddeeeeffff00001111-2222333344445555-01",
        url: "http://ork.example/Network/Authentication/Users/GetReservers/uid123",
        endpoint: "/Network/Authentication/Users/GetReservers/uid123",
        method: "GET",
        ...extra,
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

test("promotion: unanimous reserved code is promoted, representative = median minutes", async () => {
    const failures = [reservedFailure("1"), reservedFailure("5"), reservedFailure("3")];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));

    assert.equal(err.name, "TideError", "promoted error must keep the TideError name invariant");
    assert.equal(err.code, RESERVED_CODE);
    assert.equal(err.messageKey, RESERVED_KEY, "in-namespace messageKey must survive promotion");
    assert.deepEqual(err.messageParams, { minutes: "3" },
        "representative must be the failure with the MEDIAN numeric minutes");
    assert.equal(err.httpStatus, 409);
    assert.equal(err.traceId, "00-aaaabbbbccccddddeeeeffff00001111-2222333344445555-01");
    assert.match(err.source, /promoted: 3 identical per-ORK failures/);
    assert.equal(err.details.length, 3, "aggregate details must be preserved");
    assert.equal(err.cause, failures[2], "cause must be the representative (median) failure");
});

test("promotion: one inflated outlier never wins — median picks an honest value", async () => {
    // 5-member cohort, 1 attacker inflating `minutes`: median is honest.
    const failures = [
        reservedFailure("2"), reservedFailure("3"), reservedFailure("999999"),
        reservedFailure("2"), reservedFailure("3"),
    ];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));
    assert.equal(err.code, RESERVED_CODE);
    assert.ok(["2", "3"].includes(err.messageParams.minutes),
        `median must be an honest value, got minutes=${err.messageParams.minutes}`);
});

test("promotion: non-finite minutes ('9e999' / 'Infinity' / 'NaN') are never candidates", async () => {
    const failures = [reservedFailure("9e999"), reservedFailure("Infinity"),
        reservedFailure("NaN"), reservedFailure("4")];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));
    assert.equal(err.code, RESERVED_CODE);
    assert.equal(err.messageParams.minutes, "4",
        "the only finite value must be the representative; 9e999/Infinity must never win");
});

test("promotion: even candidate count takes the lower median", async () => {
    const failures = [reservedFailure("1"), reservedFailure("2"), reservedFailure("3"), reservedFailure("4")];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));
    assert.equal(err.messageParams.minutes, "2", "even count -> lower median");
});

test("promotion: no numeric minutes falls back to median expirySeconds (older ORKs)", async () => {
    const failures = [
        reservedFailure(undefined, { messageParams: { expirySeconds: "100" } }),
        reservedFailure(undefined, { messageParams: { expirySeconds: "300" } }),
        reservedFailure(undefined, { messageParams: { expirySeconds: "200" } }),
    ];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));
    assert.equal(err.code, RESERVED_CODE);
    assert.deepEqual(err.messageParams, { expirySeconds: "200" },
        "expirySeconds fallback must also be median-selected");
});

test("promotion: neither minutes nor expirySeconds numeric falls back to first failure", async () => {
    const noParams = reservedFailure(undefined);
    const nanParams = reservedFailure(undefined, { messageParams: { expirySeconds: "not-a-number" } });
    const err = await expectThrow(() => raceWith([noParams, nanParams], { promoteUnanimousCodes: true }));
    assert.equal(err.code, RESERVED_CODE);
    assert.equal(err.cause, noParams);
});

test("promotion: partial failure set at timeout does NOT promote (Finding 1 reproducer)", async () => {
    // One fast "malicious" ORK rejects with the reserved code; the other two
    // honest ORKs never answer before the timeout. The failure set is
    // unanimous-LOOKING but covers only 1 of 3 attempted — must NOT promote.
    const hang = () => new Promise(() => {});
    const promises = [Promise.reject(reservedFailure("3")), hang(), hang()];
    const err = await expectThrow(() =>
        WaitForNumberofORKs([], promises, "CMK", 3, null, null, 50, null, { promoteUnanimousCodes: true }));
    assert.equal(err.code, TideJsErrorCodes.NET_THRESHOLD_FAILURE,
        "truncated failure set must fall through to the generic aggregate");
    assert.equal(err.details.length, 1);
});

test("promotion: failures + a success below threshold does NOT promote", async () => {
    // 2 unanimous failures + 1 resolved promise, threshold 3: the failure set
    // does not cover the attempted cohort (one member SUCCEEDED), so no
    // cohort-attested claim can be made.
    const promises = [
        Promise.reject(reservedFailure("3")),
        Promise.reject(reservedFailure("3")),
        Promise.resolve({ ok: true, index: 0 }),
    ];
    const err = await expectThrow(() =>
        WaitForNumberofORKs([], promises, "CMK", 3, null, null, 50, null, { promoteUnanimousCodes: true }));
    assert.equal(err.code, TideJsErrorCodes.NET_THRESHOLD_FAILURE);
});

test("promotion: messageKey outside error(s).tide.* namespace is omitted", async () => {
    const failures = [
        reservedFailure("3", { messageKey: "enclave.login.welcomeBack" }),
        reservedFailure("3", { messageKey: "enclave.login.welcomeBack" }),
    ];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));
    assert.equal(err.code, RESERVED_CODE, "promotion itself must still happen");
    assert.equal(err.messageKey, null,
        "out-of-namespace messageKey must be omitted from the promoted error");
});

test("promotion: errors.tide.* (plural) namespace prefix is also accepted", async () => {
    const key = "errors.tide.ork.keygen.username_reserved";
    const failures = [reservedFailure("3", { messageKey: key }), reservedFailure("3", { messageKey: key })];
    const err = await expectThrow(() => raceWith(failures, { promoteUnanimousCodes: true }));
    assert.equal(err.messageKey, key);
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
