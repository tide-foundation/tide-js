// Node unit tests for the optional policy expiry (index 7 of a policy's signed data).
//
// The field is only appended when set, so a policy without an expiry must
// serialise byte-identically to how it did before the field existed.
//
// Runs against the compiled `dist/` output (see the `test` script in package.json).
import { test } from "node:test";
import assert from "node:assert/strict";

import { Policy, ApprovalType, ExecutionType } from "../dist/Models/Policy.js";

const base = {
    version: "4",
    contractId: "contract-1",
    modelId: ["model-1"],
    keyId: "key-1",
    approvalType: ApprovalType.EXPLICIT,
    executionType: ExecutionType.PUBLIC,
    params: new Map([["threshold", 1]]),
};

const make = (expiry) => new Policy(expiry === undefined ? { ...base } : { ...base, expiry });

test("a policy without an expiry round-trips unchanged", () => {
    const p = make(undefined);
    const rt = Policy.from(p.toBytes());

    assert.equal(rt.expiry, undefined);
    assert.equal(rt.hasExpired(), false);
    assert.deepEqual(Buffer.from(rt.toBytes()), Buffer.from(p.toBytes()));
});

test("an expiry round-trips", () => {
    const p = make(1893456000n);
    const rt = Policy.from(p.toBytes());

    assert.equal(rt.expiry, 1893456000n);
    assert.deepEqual(Buffer.from(rt.dataToVerify), Buffer.from(p.dataToVerify));
});

test("an expiry is accepted as a number", () => {
    assert.equal(make(1893456000).expiry, 1893456000n);
});

test("the expiry is covered by dataToVerify", () => {
    assert.notDeepEqual(Buffer.from(make(1000n).dataToVerify), Buffer.from(make(2000n).dataToVerify));
    assert.notDeepEqual(Buffer.from(make(undefined).dataToVerify), Buffer.from(make(1000n).dataToVerify));
});

test("hasExpired reflects the expiry", () => {
    const now = BigInt(Math.floor(Date.now() / 1000));

    assert.equal(make(now - 1n).hasExpired(), true);
    assert.equal(make(now + 3600n).hasExpired(), false);
    assert.equal(make(undefined).hasExpired(), false);
});
