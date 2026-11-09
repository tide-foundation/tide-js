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

// No user-facing string may contain an em dash (U+2014). Checks the title + every
// key AND value in the details map.
function assertNoEmDash(builder: any, name: string) {
    const title = String(builder._humanReadableName ?? "");
    const details = builder.getDetailsMap();
    let bad = title.includes("—");
    if (!bad && details && typeof details === "object") {
        for (const k of Object.keys(details)) {
            if (String(k).includes("—") || String(details[k]).includes("—")) { bad = true; break; }
        }
    }
    check(`${name}: no em dash in any user-facing string`, !bad, title + " | " + JSON.stringify(details));
}

// No details value may be a raw `row=key=value;...` blob, and no raw UUID may
// appear as a PRIMARY field value (a value matching the canonical UUID shape that
// is not under the secondary "Technical id" label).
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
function assertNoRawBlobOrPrimaryUuid(builder: any, name: string) {
    const details = builder.getDetailsMap();
    let blob = false, primaryUuid = false;
    if (details && typeof details === "object") {
        for (const k of Object.keys(details)) {
            const v = String(details[k]);
            if (/row=/.test(v) || /^\s*\w+=\w+;/.test(v)) blob = true;
            if (k !== "Technical id" && UUID_RE.test(v.trim())) primaryUuid = true;
        }
    }
    check(`${name}: no row= blob in details`, !blob, JSON.stringify(details));
    check(`${name}: no raw UUID as a primary field`, !primaryUuid, JSON.stringify(details));
}

console.log("AttestationUnit safe-label tests:");

// 1) client_config-only draft -> "Approve change: client config", never a grant
{
    const unit = cbor({ unit_type: 1 /* client_config */, payload: { client_id: "my-client" } });
    const b = ModelRegistry.getHumanReadableModelBuilder("r1", buildRequest([unit]));
    check("client_config title", b._humanReadableName === "Approve change: client config", b._humanReadableName);
    assertNoGrant(b, "client_config");
    assertNoEmDash(b, "client_config");
}

// 2) empty draft -> neutral "Governance change", never a grant
{
    const b = ModelRegistry.getHumanReadableModelBuilder("r2", buildRequest([]));
    check("empty draft title", b._humanReadableName === "Governance change", b._humanReadableName);
    assertNoGrant(b, "empty");
    assertNoEmDash(b, "empty");
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
        b._humanReadableName === 'Update the roles for user "alice"', b._humanReadableName);
    assertNoGrant(b, "user_role_mapping_set");
    assertNoEmDash(b, "user_role_mapping_set");
    const details = b.getDetailsMap();
    check("urms details User = alice", details["User"] === "alice", details["User"]);
    check("urms details Roles resolved", typeof details["Roles after this change"] === "string" && details["Roles after this change"].includes("tide-realm-admin"), details["Roles after this change"]);
    check("urms details has no Action key", details["Action"] === undefined, details["Action"]);
    check("urms details has resulting-set note", typeof details["Note"] === "string" && !/grant|revok/i.test(details["Note"]), details["Note"]);
}

// 3b) user_role_mapping_set WITHOUT context -> neutral generic, no UUID-grant
{
    const unit = cbor({
        unit_type: 7,
        payload: { user_id: "user-uuid-1", role_ids: ["role-uuid-a"] },
    });
    const b = ModelRegistry.getHumanReadableModelBuilder("r3b", buildRequest([unit]));
    check("urms no-context title neutral",
        b._humanReadableName === "Update the roles for a user", b._humanReadableName);
    assertNoGrant(b, "user_role_mapping_set-no-ctx");
    assertNoEmDash(b, "user_role_mapping_set-no-ctx");
}

// ---- canonicalizeNode plaintext: TRUE action rendered from signed bytes -----

// 4) DELETE_CLIENT node -> 'Delete the app "<clientId>"' + friendly fields +
//    destructive WARNING; NO row= blob, NO raw UUID as a primary field.
{
    const text = "node=DELETE_CLIENT\nentityType=CLIENT\nentityId=11111111-2222-3333-4444-555555555555\n" +
        "row=CLIENT_ID=acme-portal;CLIENT_UUID=11111111-2222-3333-4444-555555555555;REALM_NAME=acme;REALM_ID=r1\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r4", buildPlaintextRequest(text));
    check("DELETE_CLIENT title friendly+quoted",
        b._humanReadableName === 'Delete the app "acme-portal"', b._humanReadableName);
    const d = b.getDetailsMap();
    check("DELETE_CLIENT details friendly verb", d["You are about to"] === "Delete an app", d["You are about to"]);
    check("DELETE_CLIENT details App = name", d["App"] === "acme-portal", d["App"]);
    check("DELETE_CLIENT details Realm = name", d["Realm"] === "acme", d["Realm"]);
    check("DELETE_CLIENT flagged destructive w/ consequence",
        typeof d["WARNING"] === "string" && /permanently removes the app/.test(d["WARNING"]), d["WARNING"]);
    check("DELETE_CLIENT no raw Action key", d["Action"] === undefined, d["Action"]);
    assertNoGrant(b, "DELETE_CLIENT");
    assertNoEmDash(b, "DELETE_CLIENT");
    assertNoRawBlobOrPrimaryUuid(b, "DELETE_CLIENT");
}

// 4b) DELETE_USER node -> 'Delete the user "<username>"'
{
    const text = "node=DELETE_USER\nentityType=USER\nentityId=u1\nrow=REALM_ID=r1;USERNAME=bob;USER_ID=u1\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r4b", buildPlaintextRequest(text));
    check("DELETE_USER title uses username",
        b._humanReadableName === 'Delete the user "bob"', b._humanReadableName);
    const d = b.getDetailsMap();
    check("DELETE_USER details User = name", d["User"] === "bob", d["User"]);
    assertNoGrant(b, "DELETE_USER");
    assertNoEmDash(b, "DELETE_USER");
    assertNoRawBlobOrPrimaryUuid(b, "DELETE_USER");
}

// 5) DISABLE_IGA node -> fixed realm title + governance-off consequence
{
    const text = "node=DISABLE_IGA\nentityType=REALM\nentityId=r1\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r5", buildPlaintextRequest(text));
    check("DISABLE_IGA title",
        b._humanReadableName === "Turn off governance (QEA) for this realm", b._humanReadableName);
    const d = b.getDetailsMap();
    check("DISABLE_IGA flagged destructive w/ consequence",
        typeof d["WARNING"] === "string" && /turns off approval governance/.test(d["WARNING"]), d["WARNING"]);
    assertNoGrant(b, "DISABLE_IGA");
    assertNoEmDash(b, "DISABLE_IGA");
    assertNoRawBlobOrPrimaryUuid(b, "DISABLE_IGA");
}

// 5c) OFFBOARD_REALM node -> friendly title + unrecoverable consequence
{
    const text = "node=OFFBOARD_REALM\nentityType=REALM\nentityId=r1\nrow=REALM_NAME=acme\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r5c", buildPlaintextRequest(text));
    check("OFFBOARD_REALM title",
        b._humanReadableName === "Offboard (permanently shut down) this realm", b._humanReadableName);
    const d = b.getDetailsMap();
    check("OFFBOARD_REALM consequence cannot be undone",
        typeof d["WARNING"] === "string" && /cannot be undone/i.test(d["WARNING"]), d["WARNING"]);
    check("OFFBOARD_REALM realm name shown", d["Realm"] === "acme", d["Realm"]);
    assertNoGrant(b, "OFFBOARD_REALM");
    assertNoEmDash(b, "OFFBOARD_REALM");
    assertNoRawBlobOrPrimaryUuid(b, "OFFBOARD_REALM");
}

// 5b) unknown node=FOO -> honest "Governance change: FOO", never a grant
{
    const text = "node=FOO_BAR\nentityType=THING\nentityId=x1\nrow=K=v\n";
    const b = ModelRegistry.getHumanReadableModelBuilder("r5b", buildPlaintextRequest(text));
    check("unknown node honest title",
        b._humanReadableName === "Governance change: FOO_BAR", b._humanReadableName);
    const d = b.getDetailsMap();
    check("unknown node details honest verb", d["You are about to"] === "Apply governance action: FOO_BAR", d["You are about to"]);
    assertNoGrant(b, "unknown-node");
    assertNoEmDash(b, "unknown-node");
    assertNoRawBlobOrPrimaryUuid(b, "unknown-node");
}

// ---- canonicalizeLinkageSet plaintext: NEUTRAL set, no grant/revoke assertion -

// 6) linkage set -> neutral role/membership update + resolved members, NO verb
{
    const text = "table=user_role_mapping\nowner=user-uuid-1\nmembers=role-uuid-a,role-uuid-b\n";
    const ctx = { users: { "user-uuid-1": "alice" }, roles: { "role-uuid-a": "tide-realm-admin", "role-uuid-b": "viewer" } };
    const b = ModelRegistry.getHumanReadableModelBuilder("r6", buildPlaintextRequest(text), ctx);
    check("linkage title neutral+named",
        b._humanReadableName === 'Update the roles for user "alice"', b._humanReadableName);
    assertNoGrant(b, "linkage-set");
    assertNoEmDash(b, "linkage-set");
    const d = b.getDetailsMap();
    check("linkage details For = alice", d["For"] === "alice", d["For"]);
    check("linkage roles-after resolved",
        typeof d["Roles after this change"] === "string" && d["Roles after this change"].includes("tide-realm-admin"), d["Roles after this change"]);
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
        b._humanReadableName === "Update the roles for a user", b._humanReadableName);
    check("linkage empty members shows (none)",
        b.getDetailsMap()["Roles after this change"] === "(none)", b.getDetailsMap()["Roles after this change"]);
    assertNoGrant(b, "linkage-empty");
    assertNoEmDash(b, "linkage-empty");
}

console.log(failures === 0
    ? "\nALL PASS"
    : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
