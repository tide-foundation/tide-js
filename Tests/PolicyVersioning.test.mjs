// The expiry was added by bumping the policy version rather than appending an optional field to
// version 3. These tests pin the two properties that decision buys: a version 3 policy still
// verifies against the bytes it was signed over, and neither version quietly accepts a section
// it cannot interpret.
import { test } from "node:test";
import assert from "node:assert/strict";

import { Policy, ApprovalType, ExecutionType } from "../dist/Models/Policy.js";
import { TideMemory } from "../dist/Tools/TideMemory.js";
import { StringToUint8Array } from "../dist/Cryptide/Serialization.js";

const params = () => new Map([["threshold", 1]]);

// Builds a policy payload the way version 3 did, optionally with a trailing section.
function v3Payload(trailing) {
    const sections = [
        StringToUint8Array("3"),
        StringToUint8Array("contract-1"),
        TideMemory.CreateFromArray([StringToUint8Array("model-1")]),
        StringToUint8Array("key-1"),
        StringToUint8Array("EXPLICIT"),
        StringToUint8Array("PUBLIC"),
        new Policy({
            version: "4", contractId: "c", modelId: ["m"], keyId: "k",
            approvalType: ApprovalType.EXPLICIT, executionType: ExecutionType.PUBLIC, params: params(),
        }).params.toBytes(),
    ];
    if (trailing) sections.push(trailing);

    return TideMemory.CreateFromArray([TideMemory.CreateFromArray(sections)]);
}

test("new policies are version 4", () => {
    assert.equal(Policy.latestVersion, "4");
    assert.equal(new Policy({
        version: "4", contractId: "contract-1", modelId: ["model-1"], keyId: "key-1",
        approvalType: ApprovalType.EXPLICIT, executionType: ExecutionType.PUBLIC, params: params(),
    }).version, "4");
});

test("a version 3 policy still parses", () => {
    const parsed = Policy.from(v3Payload());

    assert.equal(parsed.version, "3");
    assert.equal(parsed.contractId, "contract-1");
    assert.equal(parsed.keyId, "key-1");
    assert.equal(parsed.expiry, undefined);
    assert.equal(parsed.hasExpired(), false);
});

test("a version 3 policy verifies against the bytes it was signed over", () => {
    const wire = v3Payload();
    const parsed = Policy.from(wire);

    assert.deepEqual(Buffer.from(parsed.dataToVerify), Buffer.from(wire.GetValue(0)));
    assert.deepEqual(Buffer.from(parsed.toBytes()), Buffer.from(wire));
});

test("a version 3 policy rejects a section it cannot interpret", () => {
    assert.throws(() => Policy.from(v3Payload(new Uint8Array(8))), /past the end of its layout/);
});

test("a version 4 policy rejects a section it cannot interpret", () => {
    const v4 = new Policy({
        version: "4", contractId: "contract-1", modelId: ["model-1"], keyId: "key-1",
        approvalType: ApprovalType.EXPLICIT, executionType: ExecutionType.PUBLIC,
        params: params(), expiry: 1893456000n,
    });

    const sections = [];
    const returnObj = { result: undefined };
    for (let i = 0; v4.dataToVerify.TryGetValue(i, returnObj); i++) sections.push(returnObj.result);
    sections.push(new Uint8Array(8));

    const tampered = TideMemory.CreateFromArray([TideMemory.CreateFromArray(sections)]);

    assert.throws(() => Policy.from(tampered), /past the end of its layout/);
});

test("an unknown version is rejected", () => {
    const payload = TideMemory.CreateFromArray([TideMemory.CreateFromArray([StringToUint8Array("99")])]);

    assert.throws(() => Policy.from(payload), /Unknown policy version: 99/);
});
