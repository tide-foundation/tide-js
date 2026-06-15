//
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
//
// Standalone verification for the "safe-label" fix to the approval-enclave
// summary builder (AttestationUnitSignRequestBuilder in Models/ModelRegistry.ts).
//
// Run with:  npx tsx Tests/ModelRegistryLabels.ts
//
// Asserts that NOTHING ever falsely renders as a grant:
//   - a client_config-only draft  -> "Approve change - client config" (NOT a grant)
//   - an empty / undecodable draft -> neutral "Governance change"
//   - a user_role_mapping_set draft -> neutral "Role assignment update ..." + Roles
//

import { ModelRegistry } from "../Models/ModelRegistry";
import BaseTideRequest from "../Models/BaseTideRequest";
import { CreateTideMemoryFromArray } from "../Cryptide/Serialization";

// ---- tiny CBOR encoder (definite-length) for fixtures ----------------------
// Mirrors the small subset decodeCbor() in ModelRegistry handles: unsigned ints,
// text strings, arrays and maps.
function head(major: number, n: number): number[] {
    if (n < 24) return [(major << 5) | n];
    if (n < 0x100) return [(major << 5) | 24, n];
    if (n < 0x10000) return [(major << 5) | 25, (n >> 8) & 0xff, n & 0xff];
    return [(major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}
function enc(v: any): number[] {
    if (typeof v === "number") return head(0, v);
    if (typeof v === "string") {
        const b = Array.from(new TextEncoder().encode(v));
        return [...head(3, b.length), ...b];
    }
    if (Array.isArray(v)) {
        const out = head(4, v.length);
        for (const item of v) out.push(...enc(item));
        return out;
    }
    if (v && typeof v === "object") {
        const keys = Object.keys(v);
        const out = head(5, keys.length);
        for (const k of keys) { out.push(...enc(k)); out.push(...enc(v[k])); }
        return out;
    }
    throw new Error("unsupported fixture value: " + String(v));
}
function cbor(v: any): Uint8Array { return new Uint8Array(enc(v)); }

// Build an encoded AttestationUnit:1 request whose draft segments are the given
// verbatim-CBOR unit byte arrays (req.SetUnits(byte[][]) on the producer side).
function buildRequest(unitBytesList: Uint8Array[]): Uint8Array {
    const draft = unitBytesList.length
        ? CreateTideMemoryFromArray(unitBytesList)
        : new Uint8Array();
    const req = new BaseTideRequest("AttestationUnit", "1", "", draft);
    return req.encode();
}

// ---- assertions -------------------------------------------------------------
let failures = 0;
function check(name: string, cond: boolean, extra?: any) {
    if (cond) { console.log(`  PASS  ${name}`); }
    else { console.log(`  FAIL  ${name}`, extra ?? ""); failures++; }
}
function assertNoGrant(builder: any, name: string) {
    const title = String(builder._humanReadableName ?? "");
    const detailsStr = JSON.stringify(builder.getDetailsMap());
    check(`${name}: title has no 'grant'`, !/grant/i.test(title), title);
    check(`${name}: details have no 'grant'`, !/grant/i.test(detailsStr), detailsStr);
}

console.log("AttestationUnit safe-label tests:");

// 1) client_config-only draft -> "Approve change - client config", never a grant
{
    const unit = cbor({ unit_type: 1 /* client_config */, payload: { client_id: "my-client" } });
    const b = ModelRegistry.getHumanReadableModelBuilder("r1", buildRequest([unit]));
    check("client_config title", b._humanReadableName === "Approve change - client config", b._humanReadableName);
    assertNoGrant(b, "client_config");
}

// 2) empty draft -> neutral "Governance change", never a grant
{
    const b = ModelRegistry.getHumanReadableModelBuilder("r2", buildRequest([]));
    check("empty draft title", b._humanReadableName === "Governance change", b._humanReadableName);
    assertNoGrant(b, "empty");
}

// 2b) undecodable / garbage draft -> neutral "Governance change", never a grant
{
    const garbage = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
    const b = ModelRegistry.getHumanReadableModelBuilder("r2b", buildRequest([garbage]));
    check("garbage draft title", b._humanReadableName === "Governance change", b._humanReadableName);
    assertNoGrant(b, "garbage");
}

// 2c) unknown unit_type ordinal -> "Approve change - 99", never a grant
{
    const unit = cbor({ unit_type: 99, payload: {} });
    const b = ModelRegistry.getHumanReadableModelBuilder("r2c", buildRequest([unit]));
    check("unknown ordinal not a grant", !/grant/i.test(String(b._humanReadableName)), b._humanReadableName);
    assertNoGrant(b, "unknown-ordinal");
}

// 3) user_role_mapping_set draft -> neutral role-assignment wording + Roles,
//    NEVER "Grant"
{
    const unit = cbor({
        unit_type: 7 /* user_role_mapping_set */,
        payload: { user_id: "user-uuid-1", role_ids: ["role-uuid-a", "role-uuid-b"] },
    });
    const ctx = { users: { "user-uuid-1": "alice" }, roles: { "role-uuid-a": "tide-realm-admin" } };
    const b = ModelRegistry.getHumanReadableModelBuilder("r3", buildRequest([unit]), ctx);
    check("urms title neutral+named",
        b._humanReadableName === "Role assignment update for alice", b._humanReadableName);
    assertNoGrant(b, "user_role_mapping_set");
    const details = b.getDetailsMap();
    check("urms details Target User = alice", details["Target User"] === "alice", details["Target User"]);
    check("urms details Roles resolved", typeof details["Roles"] === "string" && details["Roles"].includes("tide-realm-admin"), details["Roles"]);
    check("urms details has no Action key", details["Action"] === undefined, details["Action"]);
}

// 3b) user_role_mapping_set WITHOUT context -> neutral generic, no UUID-grant
{
    const unit = cbor({
        unit_type: 7,
        payload: { user_id: "user-uuid-1", role_ids: ["role-uuid-a"] },
    });
    const b = ModelRegistry.getHumanReadableModelBuilder("r3b", buildRequest([unit]));
    check("urms no-context title neutral",
        b._humanReadableName === "Role assignment update", b._humanReadableName);
    assertNoGrant(b, "user_role_mapping_set-no-ctx");
}

console.log(failures === 0
    ? "\nALL PASS"
    : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
