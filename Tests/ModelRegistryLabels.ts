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

// Build an AttestationUnit:1 request whose single draft segment is the verbatim
// UTF-8 plaintext that iga-core's canonicalizeNode / canonicalizeLinkageSet emits
// (the non-producer carrier path: SetUnits(new byte[][]{ canonicalForRegularCr })).
function buildPlaintextRequest(text: string): Uint8Array {
    const seg = new TextEncoder().encode(text);
    return buildRequest([seg]);
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

// ---- canonicalizeNode plaintext: TRUE action rendered from signed bytes -----

// 4) DELETE_CLIENT node -> "Delete app <clientId>" + rows + destructive WARNING
{
    const text = "node=DELETE_CLIENT\nentityType=CLIENT\nentityId=client-uuid\n" +
        "row=CLIENT_ID=acme;CLIENT_UUID=client-uuid;REALM_ID=r1\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r4", buildPlaintextRequest(text));
    check("DELETE_CLIENT title uses friendly clientId",
        b._humanReadableName === "Delete app acme", b._humanReadableName);
    const d = b.getDetailsMap();
    check("DELETE_CLIENT details Action", d["Action"] === "DELETE_CLIENT", d["Action"]);
    check("DELETE_CLIENT details has rows", typeof d["Details"] === "string" && d["Details"].includes("CLIENT_ID=acme"), d["Details"]);
    check("DELETE_CLIENT flagged destructive", typeof d["WARNING"] === "string" && d["WARNING"].length > 0, d["WARNING"]);
    assertNoGrant(b, "DELETE_CLIENT");
}

// 4b) DELETE_USER node -> "Delete user <username>"
{
    const text = "node=DELETE_USER\nentityType=USER\nentityId=u1\nrow=REALM_ID=r1;USERNAME=bob;USER_ID=u1\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r4b", buildPlaintextRequest(text));
    check("DELETE_USER title uses username",
        b._humanReadableName === "Delete user bob", b._humanReadableName);
    assertNoGrant(b, "DELETE_USER");
}

// 5) DISABLE_IGA node -> fixed realm title
{
    const text = "node=DISABLE_IGA\nentityType=REALM\nentityId=r1\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r5", buildPlaintextRequest(text));
    check("DISABLE_IGA title",
        b._humanReadableName === "Disable IGA governance on realm", b._humanReadableName);
    const d = b.getDetailsMap();
    check("DISABLE_IGA flagged destructive", typeof d["WARNING"] === "string" && d["WARNING"].length > 0, d["WARNING"]);
    assertNoGrant(b, "DISABLE_IGA");
}

// 5b) unknown node=FOO -> honest "Governance change: FOO", never a grant
{
    const text = "node=FOO_BAR\nentityType=THING\nentityId=x1\nrow=K=v\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r5b", buildPlaintextRequest(text));
    check("unknown node honest title",
        b._humanReadableName === "Governance change: FOO_BAR", b._humanReadableName);
    const d = b.getDetailsMap();
    check("unknown node details Action raw", d["Action"] === "FOO_BAR", d["Action"]);
    assertNoGrant(b, "unknown-node");
}

// ---- canonicalizeLinkageSet plaintext: NEUTRAL set, no grant/revoke assertion -

// 6) linkage set -> neutral role/membership update + resolved members, NO verb
{
    const text = "table=user_role_mapping\nowner=user-uuid-1\nmembers=role-uuid-a,role-uuid-b\n";
    const ctx = { users: { "user-uuid-1": "alice" }, roles: { "role-uuid-a": "tide-realm-admin", "role-uuid-b": "viewer" } };
    const b = ModelRegistry.getHumanReadableModelBuilder("r6", buildPlaintextRequest(text), ctx);
    check("linkage title neutral+named",
        b._humanReadableName === "Role/membership assignment update for alice", b._humanReadableName);
    assertNoGrant(b, "linkage-set");
    const d = b.getDetailsMap();
    check("linkage details Table", d["Table"] === "user_role_mapping", d["Table"]);
    check("linkage members resolved",
        typeof d["Members of alice"] === "string" && d["Members of alice"].includes("tide-realm-admin"), d["Members of alice"]);
    check("linkage notes resulting-set, no verb",
        typeof d["Note"] === "string" && !/revok|grant/i.test(d["Note"]), d["Note"]);
    // must NOT assert revoke either
    check("linkage title has no 'revoke'", !/revoke/i.test(String(b._humanReadableName)), b._humanReadableName);
}

// 6b) linkage set, empty resulting members -> "(none)", still neutral
{
    const text = "table=user_role_mapping\nowner=user-uuid-1\nmembers=\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r6b", buildPlaintextRequest(text));
    check("linkage empty members neutral title",
        b._humanReadableName === "Role/membership assignment update", b._humanReadableName);
    assertNoGrant(b, "linkage-empty");
}

console.log(failures === 0
    ? "\nALL PASS"
    : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
