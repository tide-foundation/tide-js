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

import { AuthorizerPack, Bytes2Hex, GetValue, StringFromUint8Array, TryGetValue } from "../Cryptide/Serialization";
import BaseTideRequest from "./BaseTideRequest";
import { Policy, ApprovalType, ExecutionType } from "./Policy";
import { Serialization } from "../Cryptide/index";
import { TideError } from "../Errors/TideError";
import { TideJsErrorCodes } from "../Errors/codes";

/**
 * Optional, DISPLAY-ONLY lookup tables the caller (the admin-ui, which already
 * holds friendly names - see keycloak-IGA formatters.humanReadableSummary) may
 * hand to the enclave so UUID-only carriers can be rendered as readable names.
 *
 * SECURITY: this NEVER participates in the signed bytes. The signed
 * AttestationUnit carries only UUIDs; these names are advisory chrome. A missing
 * entry simply falls back to the raw UUID - never blanks, never throws, and the
 * enclave must never trust these for any authorization decision.
 */
export interface HumanReadableContext {
    /** role-id (UUID) -> role name, e.g. "tide-realm-admin". */
    roles?: { [roleId: string]: string };
    /** user-id (UUID) -> username, e.g. "alice". */
    users?: { [userId: string]: string };
}

export class ModelRegistry {
    static getHumanReadableModelBuilder(reqId: string, data: Uint8Array, context?: HumanReadableContext): HumanReadableModelBuilder {
        const r = BaseTideRequest.decode(data);
        const nameMatch = r.name.match(/^BasicCustom<(.*)>$/)?.[1];
        const versionMatch = r.version.match(/^BasicCustom<(.*)>$/)?.[1];
        if (nameMatch && versionMatch) {
            return new CustomSignRequestBuilder(data, reqId, context);
        }
        const c = modelBuildersMap[r.id()];
        if (!c) throw new TideError({ code: TideJsErrorCodes.MODEL_UNKNOWN_MODEL, displayMessage: `Could not find model: ${r.id()}`, source: "tide-js/Models/ModelRegistry.ts:34" });
        return c.create(data, reqId, context);
    }
}

export class HumanReadableModelBuilder {
    _humanReadableName = null;
    _data: any;
    _draft: any;
    request: BaseTideRequest | undefined;
    reqId: any;
    // DISPLAY-ONLY names map (roleId->name, userId->username). Never signed; see
    // HumanReadableContext. Optional - undefined when the caller supplies none.
    _context: HumanReadableContext | undefined;
    constructor(data, reqId, context?: HumanReadableContext) {
        if (data) {
            this._data = data;
            this._draft = GetValue(this._data, 3);
            this.request = BaseTideRequest.decode(data);
        }
        this.reqId = reqId;
        this._context = context;
    }
    static create(data, reqId, context?: HumanReadableContext) {
        return new this(data, reqId, context);
    }
    getDetailsMap() {
        // the summary
        return [];
    }
    getRequestDataJson() {
        // raw json
        return {};
    }

    getExpiry() {
        return this.request.expiry;
    }

    async getDataToApprove() {
        return this.request.dataToApprove();
    }
}

// MODELS ----------------------------------------------------------------
class CustomSignRequestBuilder extends HumanReadableModelBuilder {
    _name: any;
    _version: any;
    humanReadableJson: any;
    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId, context?: HumanReadableContext) {
        super(data, reqId, context);
        this._name = this.request.name.match(/^BasicCustom<(.*)>$/)?.[1];
        this._version = this.request.version.match(/^BasicCustom<(.*)>$/)?.[1];
        this.humanReadableJson = JSON.parse(StringFromUint8Array(GetValue(this.request.draft, 0)));
        this._humanReadableName = this.humanReadableJson["humanReadableName"];
    }
    getRequestDataJson(){
        return this.humanReadableJson["additionalInfo"];
    }
}
// Need this while we work on better custom models
class HederaSignRequestBuilder extends HumanReadableModelBuilder {
    _name = "HederaTx";
    _version = "1";
    customInfo: any;
    additionalInfo: any;
    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId) {
        super(data, reqId);
        if(data){
            this.customInfo = JSON.parse(StringFromUint8Array(Serialization.GetValue(this.request.draft, 0)));
            this.additionalInfo = this.customInfo["additionalInfo"];
            this._humanReadableName = `Request to send ${BigInt(this.additionalInfo["Total being spent (tinybar)"]) / BigInt(100_000_000)} HBAR`;
        }
    }
    getRequestDataJson(){
        return this.additionalInfo;
    }
}

export class OffboardSignRequestBuilder extends HumanReadableModelBuilder {
    _name = "Offboard";
    _version = "1";
    _humanReadableName = "Offboard from the Tide network (cancel subscription and protection)";

    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId) {
        super(data, reqId);
    }
    getDetailsMap(): any {
        let summary: any = {};
        summary["WARNING"] = "Warning: approving this offboards your account from the Tide network. It cancels your subscription and Tide protection, and cannot be undone.";
        summary["You are about to"] = "Offboard this account from the Tide network";
        summary["Note"] = "Only approve this if you intend to permanently offboard from the Tide network.";
        return summary;
    }
    getRequestDataJson() {
        const vrk = Bytes2Hex(GetValue(this._draft, 0));
        let body = {
            "Vendor Rotating Key for Offboarding": vrk
        }
        return body;
    }
}

class PolicySignRequestBuilder extends HumanReadableModelBuilder {
    _name = "Policy";
    _version = "1";
    _humanReadableName = "Approve new policy for use with Tide";
    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry) {
        super(data, expiry);
        // Make the card title context-aware. The admin-threshold re-sign
        // (REGEN_ADMIN_POLICY) carries a Policy whose contractId is
        // "GenericResourceAccessThresholdRole:1" and whose params scope the
        // tide-realm-admin role on the realm-management resource (see iga-core
        // TideAttestor.buildAdminPolicy* - POLICY_TYPE / TIDE_REALM_ADMIN_ROLE /
        // POLICY_RESOURCE). When we can detect that exact shape from the carrier,
        // show a specific title; otherwise keep the generic one. Display-only and
        // fully guarded - a decode failure must never change the signed bytes nor
        // throw out of the constructor.
        try {
            const policy = this._tryGetPolicy();
            if (policy && this._isAdminThresholdPolicy(policy)) {
                this._humanReadableName = "Update admin approval threshold (re-sign tide-realm-admin policy)";
            }
        } catch { /* keep the generic title */ }
    }

    // Decode the Policy carried in draft[0], or null if absent/undecodable.
    private _tryGetPolicy(): Policy | null {
        try {
            if (!this._draft) return null;
            const policyBytes = GetValue(this._draft, 0);
            if (!policyBytes || policyBytes.length === 0) return null;
            return Policy.from(policyBytes);
        } catch { return null; }
    }

    // True when the Policy is the multiAdmin tide-realm-admin approval-threshold
    // policy. Keyed on the producer-stamped contractId
    // ("GenericResourceAccessThresholdRole:1") PLUS the role/resource params, so
    // an ordinary GenericResourceAccessThresholdRole policy for some OTHER
    // role/resource still falls through to the generic title.
    private _isAdminThresholdPolicy(policy: Policy): boolean {
        try {
            if (policy.contractId !== "GenericResourceAccessThresholdRole:1") return false;
            const role = policy.params?.entries?.get("role");
            const resource = policy.params?.entries?.get("resource");
            return role === "tide-realm-admin" && resource === "realm-management";
        } catch { return false; }
    }

    getDetailsMap(): any {
        let summary: any = {};

        const draftBytes = this._draft;
        if (!draftBytes) return { error: 'No draft data' };

        const policyBytes = GetValue(draftBytes, 0);
        const policy = Policy.from(policyBytes);

        // For the admin-threshold re-sign, surface the new threshold up front
        // (the only human-meaningful change in the policy). The Policy carries
        // the NEW threshold in its params; the OLD value is NOT in the signed
        // carrier (it lives in the CR ROWS_JSON, which the enclave never sees),
        // so we show only what the carrier actually proves.
        if (this._isAdminThresholdPolicy(policy)) {
            const threshold = policy.params?.entries?.get("threshold");
            if (threshold !== undefined && !(threshold instanceof Uint8Array)) {
                summary["New admin approvals required"] = threshold;
            }
        }

        summary['Version'] = policy.version;
        summary['ContractId'] = policy.contractId;
        summary['ModelId'] = policy.modelIds.join(", ");
        summary["KeyId"] = policy.keyId;
        summary['Approval Type'] = ApprovalType[policy.approvalType];
        summary["Execution Type"] = ExecutionType[policy.executionType];

        // WHEN THE THING BEING APPROVED STOPS BEING VALID.
        //
        // Shown here, from the policy in the draft, because that is the policy this request is
        // asking to have signed. The card's own "Policy Expiry" line reads the request's attached
        // policy, which on a policy signature is the EXISTING one authorising the approval - a
        // different policy, and for the admin policy always an unexpiring one. An approver reading
        // that line next to a policy approval reads it as this, and would be told "Never" about
        // something that expires in days.
        summary['Expiry'] = policy.expiry === undefined
            ? 'Never'
            : new Date(Number(policy.expiry) * 1000).toUTCString();
        for (const [key, value] of policy.params.entries.entries()) {
            if (!(value instanceof Uint8Array)) summary[`Parameter:${key}`] = value;
        }

        // draft[1] is OPTIONAL. For a contract-upload policy it holds the
        // contractTransport structure; for an admin-threshold policy re-sign it is
        // an EMPTY (0-byte) placeholder whose only purpose is to position draft[2]
        // (the ORK's revoke-authorizing-policy flag). Only parse it as a contract
        // when it actually carries a length-prefixed structure (>= 4 bytes for a
        // TideMemory header) - an empty segment must be skipped, not read.
        let res: any = {};
        if (TryGetValue(draftBytes, 1, res) && res.result && res.result.length >= 4) {
            const contractBytes = res.result;
            const contractType = StringFromUint8Array(GetValue(contractBytes, 0));
            summary["Contract To Upload Type"] = contractType;
            summary["Contract Included"] = "Yes - see Request Data for source code";
        }
        return summary;
    }

    getRequestDataJson() {
        let data: any = {};

        const draftBytes = this._draft;
        if (!draftBytes) return data;

        // Only show contract source code - other info is in the summary
        // Structure: draft[1] = contractTransport = ["forseti", forsetiData]
        // forsetiData = [placeholder, innerPayload]
        // innerPayload = [sourceCode, entryType?]
        let res: any = {};
        if (TryGetValue(draftBytes, 1, res) && res.result && res.result.length >= 4) {
            const contractBytes = res.result;

            // contractBytes[1] = forsetiData
            let forsetiDataRes: any = {};
            if (TryGetValue(contractBytes, 1, forsetiDataRes)) {
                const forsetiData = forsetiDataRes.result;

                // forsetiData[1] = innerPayload
                let innerPayloadRes: any = {};
                if (TryGetValue(forsetiData, 1, innerPayloadRes)) {
                    const innerPayload = innerPayloadRes.result;

                    // innerPayload[0] = sourceCode
                    let sourceCodeRes: any = {};
                    if (TryGetValue(innerPayload, 0, sourceCodeRes)) {
                        const contractCode = StringFromUint8Array(sourceCodeRes.result);
                        data["Contract Source Code"] = contractCode;
                    }
                }
            }
        }

        return data;
    }
}

class PolicyEnabledEncryptionRequestBuilder extends HumanReadableModelBuilder {
     _name = "PolicyEnabledEncryption";
    _version = "1";
    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry) {
        super(data, expiry);
        if(data){
            const timestamp = GetValue(this.request.draft, 0);
            let resultObj = {result: undefined};
            let i = 1;
            while(TryGetValue(this.request.draft, i, resultObj)){i++;}
            const count = i - 1; // subtract 1 as i starts at 1 (skipping timestamp)
            this._humanReadableName = `Encrypt ${count} piece${count != 1 ? "s" : ""} of data`
        }
    }
}

class PolicyEnabledDecryptionRequestBuilder extends HumanReadableModelBuilder {
     _name = "PolicyEnabledDecryption";
    _version = "1";
    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry) {
        super(data, expiry);
        if(data){
            let resultObj = {result: undefined};
            let i = 0;
            while(TryGetValue(this.request.draft, i, resultObj)){i++;}
            this._humanReadableName = `Decrypt ${i} piece${i != 1 ? "s" : ""} of data`
        }
    }
}

class LicenseSignRequestBuilder extends HumanReadableModelBuilder {
    _name = "RotateVRK";
    _version = "1";
    _humanReadableName = "Renew License with New Permissions";

    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry) {
        super(data, expiry);
    }
    getDetailsMap() {
        const authPack = new AuthorizerPack(this._draft);

        let summary: any = [];
        summary["Signing new license"] = (authPack as any).Authorizer.GVRK.Serialize().ToString();

        summary["Approved Models to Sign"] = (authPack as any).SignModels;

        return summary;
    }
}
class TestInitSignRequestBuilder extends HumanReadableModelBuilder {
    _name = "TestInit";
    _version = "1";
    _humanReadableName = "Test Tide Request";
    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry) {
        super(data, expiry);
    }
    getDetailsMap() {
        let summary: any = [];
        summary["Draft Detail"] = StringFromUint8Array(this._draft);
        return summary;
    }
}

class ServerCertSignRequestBuilder extends HumanReadableModelBuilder {
    _name = "ServerCert";
    _version = "1";
    _humanReadableName = "Server Certificate";
    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId) {
        super(data, reqId);
    }
    getDetailsMap(): any {
        let summary: any = {};

        // DynamicData is JSON bytes, parse as string
        if (this.request && this.request.dyanmicData && this.request.dyanmicData.length > 0) {
            try {
                const jsonStr = new TextDecoder().decode(this.request.dyanmicData);
                const parsed = JSON.parse(jsonStr);
                if (parsed.realm) summary["Realm"] = parsed.realm;
                if (parsed.clientId) summary["Client ID"] = parsed.clientId;
                if (parsed.instanceId) summary["Instance ID"] = parsed.instanceId;
                if (parsed.spiffeId) summary["SPIFFE ID"] = parsed.spiffeId;
            } catch { /* DynamicData not parseable as JSON */ }
        }

        return summary;
    }
    getRequestDataJson() {
        let data: any = {};
        if (this._draft && this._draft.length > 0) {
            data["TBS Certificate (DER)"] = Bytes2Hex(this._draft);
        }
        return data;
    }
}

// ---------------------------------------------------------------------------
// Minimal, dependency-free CBOR decoder.
//
// The AttestationUnit:1 draft carries one or more attestation-unit envelopes as
// VERBATIM CBOR (produced by Jackson's default CBOR mapper on the iga-core
// producer side - see RealmAttestationExporter / AttestationUnit.java). tide-js
// has no CBOR dependency, so we decode the small, well-defined subset Jackson
// emits here: unsigned/negative integers, byte/text strings, arrays, maps and
// the simple values false/true/null - definite AND indefinite length. This is
// display-only (the enclave renders the result); it never participates in the
// signed bytes, so a decode failure must degrade gracefully, never throw.
function decodeCbor(bytes: Uint8Array): any {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let pos = 0;

    function readUint(n: number): number {
        let v = 0;
        for (let i = 0; i < n; i++) { v = v * 256 + dv.getUint8(pos); pos++; }
        return v;
    }

    function readLength(ai: number): number {
        if (ai < 24) return ai;
        if (ai === 24) return readUint(1);
        if (ai === 25) return readUint(2);
        if (ai === 26) return readUint(4);
        if (ai === 27) return readUint(8); // may lose precision beyond 2^53; fine for display
        if (ai === 31) return -1;          // indefinite length
        throw new Error("Unsupported CBOR additional info: " + ai);
    }

    function readItem(): any {
        const ib = dv.getUint8(pos); pos++;
        const major = ib >> 5;
        const ai = ib & 0x1f;

        switch (major) {
            case 0: // unsigned int
                return readLength(ai);
            case 1: // negative int
                return -1 - readLength(ai);
            case 2: { // byte string
                if (ai === 31) { // indefinite chunks
                    const chunks: number[] = [];
                    while (dv.getUint8(pos) !== 0xff) { const c = readItem(); for (const b of c) chunks.push(b); }
                    pos++; // consume break
                    return new Uint8Array(chunks);
                }
                const len = readLength(ai);
                const out = bytes.subarray(pos, pos + len); pos += len;
                return new Uint8Array(out);
            }
            case 3: { // text string
                if (ai === 31) {
                    let s = "";
                    while (dv.getUint8(pos) !== 0xff) { s += readItem(); }
                    pos++;
                    return s;
                }
                const len = readLength(ai);
                const slice = bytes.subarray(pos, pos + len); pos += len;
                return new TextDecoder().decode(slice);
            }
            case 4: { // array
                const arr: any[] = [];
                if (ai === 31) { while (dv.getUint8(pos) !== 0xff) arr.push(readItem()); pos++; return arr; }
                const len = readLength(ai);
                for (let i = 0; i < len; i++) arr.push(readItem());
                return arr;
            }
            case 5: { // map
                const map: any = {};
                if (ai === 31) {
                    while (dv.getUint8(pos) !== 0xff) { const k = readItem(); map[String(k)] = readItem(); }
                    pos++;
                    return map;
                }
                const len = readLength(ai);
                for (let i = 0; i < len; i++) { const k = readItem(); map[String(k)] = readItem(); }
                return map;
            }
            case 7: // simple / float
                if (ai === 20) return false;
                if (ai === 21) return true;
                if (ai === 22) return null;      // null
                if (ai === 23) return undefined; // undefined
                if (ai === 25 || ai === 26 || ai === 27) {
                    // half/single/double float - not used by the unit envelopes; skip bytes.
                    readUint(ai === 25 ? 2 : ai === 26 ? 4 : 8);
                    return null;
                }
                return null;
            default:
                throw new Error("Unsupported CBOR major type: " + major);
        }
    }

    return readItem();
}

// Maps the integer unit_type ordinal (AttestationUnitType.wireValue, the
// authoritative producer→ork mapping) back to the snake_case wire name for
// display. Kept in lock-step with iga-core AttestationUnitType.java.
const ATTESTATION_UNIT_TYPE_NAMES: { [k: number]: string } = {
    0: "realm_config",
    1: "client_config",
    2: "client_scope_config",
    3: "protocol_mapper",
    4: "role_definition",
    5: "group_definition",
    6: "user_identity",
    7: "user_role_mapping_set",
    8: "user_group_membership_set",
    9: "group_role_mapping_set",
    10: "role_composite_children_set",
    11: "client_scope_assignment_set",
    12: "client_mapper_set",
    13: "client_scope_mapper_set",
    14: "scope_role_allowlist_set",
    15: "realm_default_groups_set",
    16: "organization_definition",
    17: "organization_domain_set",
};

// -----------------------------------------------------------------------------
// Producer "canonicalizeNode" plaintext (the NODE / non-linkage CR family).
//
// For a NON-producer CR (DELETE_*, DISABLE_IGA, ...) the carrier's draft segment
// is NOT a CBOR AttestationUnit envelope: it is the VERBATIM UTF-8 plaintext that
// iga-core's TideAttestor.canonicalizeNode emits and signs (the bytes the admin
// approves), shaped as:
//
//   node=<ACTION>\n
//   entityType=<ENTITY>\n
//   entityId=<id>\n
//   row=<k=v;k=v;...>\n        (one or more, keys sorted, rows sorted)
//
// This is FULLY self-describing — `node=<ACTION>` is the TRUE CR action, present
// in the signed bytes, so for this family we render the accurate action+data.
//
// `node` ACTION -> faithful human title. The {0} placeholder is filled from the
// most human-friendly row field for that entity (e.g. CLIENT_ID, USERNAME, NAME)
// falling back to the entityId. Verified against the producer CR creation sites
// (IgaRealmProvider / IgaUserProvider recordAndThrow rows). For an action NOT in
// this map we render the HONEST raw action ("Governance change: <node>") — never
// a fabricated grant.
const NODE_ACTION_TITLES: { [action: string]: (label: string) => string } = {
    DELETE_CLIENT: (l) => `Delete the app "${l}"`,
    DELETE_CLIENT_SCOPE: (l) => `Delete the client scope "${l}"`,
    DELETE_USER: (l) => `Delete the user "${l}"`,
    DELETE_ROLE: (l) => `Delete the role "${l}"`,
    DELETE_GROUP: (l) => `Delete the group "${l}"`,
    DELETE_ORGANIZATION: (l) => `Delete the organization "${l}"`,
    DISABLE_IGA: () => "Turn off governance (QEA) for this realm",
    OFFBOARD_REALM: () => "Offboard (permanently shut down) this realm",
    CREATE_CLIENT: (l) => `Create the app "${l}"`,
    CREATE_CLIENT_SCOPE: (l) => `Create the client scope "${l}"`,
    CREATE_USER: (l) => `Create the user "${l}"`,
    CREATE_ROLE: (l) => `Create the role "${l}"`,
    CREATE_GROUP: (l) => `Create the group "${l}"`,
    CREATE_ORGANIZATION: (l) => `Create the organization "${l}"`,
    UPDATE_CLIENT_PROPERTY: (l) => `Update the app "${l}"`,
    UPDATE_CLIENT_REDIRECT_URIS: (l) => `Update the redirect URIs for app "${l}"`,
    UPDATE_CLIENT_WEB_ORIGINS: (l) => `Update the web origins for app "${l}"`,
    UPDATE_CLIENT_SCOPE_PROPERTY: (l) => `Update the client scope "${l}"`,
    UPDATE_PROTOCOL_MAPPER: (l) => `Update the protocol mapper "${l}"`,
    UPDATE_ORGANIZATION: (l) => `Update the organization "${l}"`,
};

// Per-action, plain-language consequence line for destructive actions, styled
// with the WARNING/severity convention the enclave page already understands (see
// OffboardSignRequestBuilder). Accurate, non-alarmist, no em dashes.
const NODE_DESTRUCTIVE_WARNINGS: { [action: string]: string } = {
    DELETE_CLIENT: "Warning: this permanently removes the app and all access through it. Apps and users relying on it will stop working.",
    DELETE_CLIENT_SCOPE: "Warning: this permanently removes the client scope. Apps that depend on it may lose claims or stop working.",
    DELETE_USER: "Warning: this permanently removes the user and their access. This cannot be undone.",
    DELETE_ROLE: "Warning: this permanently removes the role. Users and groups holding it will lose the access it granted.",
    DELETE_GROUP: "Warning: this permanently removes the group. Members will lose any access the group granted.",
    DELETE_ORGANIZATION: "Warning: this permanently removes the organization and its associations. This cannot be undone.",
    DISABLE_IGA: "Warning: this turns off approval governance for the whole realm. Future admin changes will apply without approval.",
    OFFBOARD_REALM: "Warning: this permanently shuts the realm down. This cannot be undone.",
};

// Friendly, plain-language noun for the artifact each entity type refers to, used
// in the "You are about to <verb> a/an <noun>" details line and as the primary
// labelled field. Falls back to the raw entityType when not mapped.
const NODE_ENTITY_NOUNS: { [entityType: string]: string } = {
    CLIENT: "App",
    CLIENT_SCOPE: "Client scope",
    USER: "User",
    ROLE: "Role",
    GROUP: "Group",
    ORGANIZATION: "Organization",
    REALM: "Realm",
};

// Plain-language verb phrase for the "You are about to ..." details line, keyed on
// the action prefix. Keeps the consequence summary readable without a raw action.
const NODE_ACTION_VERBS: { [action: string]: string } = {
    DELETE_CLIENT: "Delete an app",
    DELETE_CLIENT_SCOPE: "Delete a client scope",
    DELETE_USER: "Delete a user",
    DELETE_ROLE: "Delete a role",
    DELETE_GROUP: "Delete a group",
    DELETE_ORGANIZATION: "Delete an organization",
    DISABLE_IGA: "Turn off governance for this realm",
    OFFBOARD_REALM: "Permanently shut this realm down",
    CREATE_CLIENT: "Create an app",
    CREATE_CLIENT_SCOPE: "Create a client scope",
    CREATE_USER: "Create a user",
    CREATE_ROLE: "Create a role",
    CREATE_GROUP: "Create a group",
    CREATE_ORGANIZATION: "Create an organization",
    UPDATE_CLIENT_PROPERTY: "Update an app",
    UPDATE_CLIENT_REDIRECT_URIS: "Update an app's redirect URIs",
    UPDATE_CLIENT_WEB_ORIGINS: "Update an app's web origins",
    UPDATE_CLIENT_SCOPE_PROPERTY: "Update a client scope",
    UPDATE_PROTOCOL_MAPPER: "Update a protocol mapper",
    UPDATE_ORGANIZATION: "Update an organization",
};

// node ACTIONs that destroy/cripple governed state — flagged in the details so the
// admin sees the same WARNING severity convention the Offboard builder uses.
const NODE_DESTRUCTIVE_ACTIONS = new Set<string>([
    "DELETE_CLIENT", "DELETE_CLIENT_SCOPE", "DELETE_USER", "DELETE_ROLE",
    "DELETE_GROUP", "DELETE_ORGANIZATION", "DISABLE_IGA", "OFFBOARD_REALM",
]);

// Preferred human-friendly row field per entityType, most-specific first. Used to
// label the title with a name the admin recognises instead of a raw UUID.
const NODE_LABEL_FIELDS: { [entityType: string]: string[] } = {
    CLIENT: ["CLIENT_ID"],
    CLIENT_SCOPE: ["CLIENT_SCOPE_NAME"],
    USER: ["USERNAME"],
    ROLE: ["ROLE_NAME"],
    GROUP: ["GROUP_NAME"],
    ORGANIZATION: ["ORG_NAME", "NAME", "ALIAS"],
    REALM: ["REALM_NAME", "NAME"],
};

// Row fields that are noisy internal identifiers (raw UUIDs / *_UUID / *_ID
// surrogate keys). These are never surfaced as primary friendly fields; at most a
// single one is tucked under a secondary "Technical id" line.
const NODE_NOISY_FIELDS = new Set<string>([
    "CLIENT_UUID", "USER_UUID", "ROLE_UUID", "GROUP_UUID", "SCOPE_UUID",
    "CLIENT_SCOPE_UUID", "ORG_UUID", "ID", "REALM_ID",
]);

// Row field, per entityType, whose value is the human-friendly NAME of the
// artifact (shown as the primary labelled field in the details map).
const NODE_PRIMARY_NAME_FIELD: { [entityType: string]: string[] } = NODE_LABEL_FIELDS;

// Parsed shape of a canonicalizeNode plaintext draft segment.
interface ParsedNodeCanonical {
    node: string;
    entityType: string | undefined;
    entityId: string | undefined;
    rows: { [k: string]: string }[];
}

// Parsed shape of a canonicalizeLinkageSet plaintext draft segment.
interface ParsedLinkageCanonical {
    table: string;
    // one entry per owner, in the order emitted; members is the resulting set.
    owners: { owner: string; members: string[] }[];
}

// UTF-8 decode the segment bytes, tolerating non-UTF-8 (returns "" on failure so
// the caller falls through to the CBOR / neutral path; never throws).
function decodeUtf8Loose(bytes: Uint8Array): string {
    try { return StringFromUint8Array(bytes); } catch { return ""; }
}

// Parse a canonicalizeNode plaintext segment. Returns undefined when the bytes are
// not the `node=...` plaintext shape (so the caller tries CBOR / neutral). Never
// throws. Mirrors iga-core TideAttestor.canonicalizeNode byte-for-byte: lines are
// '\n'-delimited; each `row=` line is `k=v;k=v;...` with `;` between pairs and the
// FIRST `=` separating key from value (values may themselves contain `=`).
function parseNodeCanonical(text: string): ParsedNodeCanonical | undefined {
    if (!text.startsWith("node=")) return undefined;
    const lines = text.split("\n");
    let node = "", entityType: string | undefined, entityId: string | undefined;
    const rows: { [k: string]: string }[] = [];
    for (const line of lines) {
        if (line.length === 0) continue;
        if (line.startsWith("node=")) node = line.substring("node=".length);
        else if (line.startsWith("entityType=")) entityType = line.substring("entityType=".length);
        else if (line.startsWith("entityId=")) entityId = line.substring("entityId=".length);
        else if (line.startsWith("row=")) {
            const body = line.substring("row=".length);
            const row: { [k: string]: string } = {};
            if (body.length > 0) {
                for (const pair of body.split(";")) {
                    const eq = pair.indexOf("=");
                    if (eq < 0) continue;
                    row[pair.substring(0, eq)] = pair.substring(eq + 1);
                }
            }
            rows.push(row);
        }
    }
    if (node.length === 0) return undefined;
    return { node, entityType, entityId, rows };
}

// Parse a canonicalizeLinkageSet plaintext segment. Returns undefined when the
// bytes are not the `table=...` plaintext shape. Never throws. Mirrors iga-core
// TideAttestor.canonicalizeLinkageSet: `table=<t>\n` then per owner
// `owner=<id>\nmembers=<m1,m2,...>\n` (members comma-joined, possibly empty).
function parseLinkageCanonical(text: string): ParsedLinkageCanonical | undefined {
    if (!text.startsWith("table=")) return undefined;
    const lines = text.split("\n");
    let table = "";
    const owners: { owner: string; members: string[] }[] = [];
    let currentOwner: string | undefined;
    for (const line of lines) {
        if (line.length === 0) continue;
        if (line.startsWith("table=")) table = line.substring("table=".length);
        else if (line.startsWith("owner=")) {
            currentOwner = line.substring("owner=".length);
            owners.push({ owner: currentOwner, members: [] });
        } else if (line.startsWith("members=")) {
            const body = line.substring("members=".length);
            const members = body.length > 0 ? body.split(",") : [];
            if (owners.length > 0) owners[owners.length - 1].members = members;
        }
    }
    if (table.length === 0) return undefined;
    return { table, owners };
}

class AttestationUnitSignRequestBuilder extends HumanReadableModelBuilder {
    _name = "AttestationUnit";
    _version = "1";
    // GENERIC, always-human-readable, ACTION-NEUTRAL fallback. The enclave
    // renderer uses `_humanReadableName ?? _name` for the card TITLE, so this MUST
    // never be a raw/opaque code (the old "AE" short code came from a stale bundle
    // that lacked this builder and fell through to the carrier short-name).
    //
    // It must ALSO never assert an action verb (grant/delete/create/update/revoke):
    // the signed draft carries only the structural `unit_type` + payloads, NOT the
    // CR action verb, so we cannot prove what is happening to the artifact from the
    // bytes. A DELETE_CLIENT / OFFBOARD_REALM / etc. must NEVER render as "grant a
    // role". The constructor refines this to a type-specific (still neutral) title
    // below; even if decoding fails the admin sees an honest "Governance change"
    // rather than a fabricated grant.
    _humanReadableName = "Governance change";
    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId, context?: HumanReadableContext) {
        super(data, reqId, context);
        // Refine the card title from the actual carried unit. Display-only and
        // fully guarded - a decode failure must never throw out of the
        // constructor nor change the signed bytes; it just keeps the generic
        // (still human-readable) title above.
        try {
            this._humanReadableName = this._buildTitle() ?? this._humanReadableName;
        } catch { /* keep the neutral "Governance change" title */ }
    }

    // Lazily decode draft segment 0 as UTF-8 and try the two producer plaintext
    // canonical shapes. Cached so repeated title/details calls parse once. Never
    // throws; returns the parsed form or undefined when the segment is not that
    // plaintext (CBOR unit, empty, or garbage), in which case callers fall through
    // to the CBOR / neutral path.
    private _nodeCanon: ParsedNodeCanonical | undefined | null = null;     // null = not yet computed
    private _linkageCanon: ParsedLinkageCanonical | undefined | null = null;
    private _firstSegmentText(): string {
        try {
            if (!this._draft) return "";
            const res: any = {};
            if (!TryGetValue(this._draft, 0, res)) return "";
            const bytes = res.result;
            if (!bytes || bytes.length === 0) return "";
            return decodeUtf8Loose(bytes);
        } catch { return ""; }
    }
    private _getNodeCanonical(): ParsedNodeCanonical | undefined {
        if (this._nodeCanon === null) {
            try { this._nodeCanon = parseNodeCanonical(this._firstSegmentText()); }
            catch { this._nodeCanon = undefined; }
        }
        return this._nodeCanon ?? undefined;
    }
    private _getLinkageCanonical(): ParsedLinkageCanonical | undefined {
        if (this._linkageCanon === null) {
            try { this._linkageCanon = parseLinkageCanonical(this._firstSegmentText()); }
            catch { this._linkageCanon = undefined; }
        }
        return this._linkageCanon ?? undefined;
    }

    // Pick the most human-friendly label for a node CR from its parsed rows
    // (e.g. CLIENT_ID, USERNAME, NAME), falling back to the entityId, then "(?)".
    private _nodeLabel(node: ParsedNodeCanonical): string {
        const fields = (node.entityType && NODE_LABEL_FIELDS[node.entityType]) || [];
        for (const row of node.rows) {
            for (const f of fields) {
                const v = row[f];
                if (typeof v === "string" && v.length > 0) return v;
            }
        }
        if (typeof node.entityId === "string" && node.entityId.length > 0
            && node.entityId !== "null") return node.entityId;
        return "(unspecified)";
    }

    // Compute a specific, human-readable card title for the carried unit, using
    // the display-only HumanReadableContext (role/user names) when present.
    //
    // HONESTY CONTRACT, by draft shape:
    //   - canonicalizeNode plaintext (`node=<ACTION>...`): the TRUE action IS in the
    //     signed bytes, so render it ACCURATELY ("Delete app my-client", "Disable
    //     IGA governance on realm"). Unknown action -> honest "Governance change:
    //     <node>", never a grant.
    //   - canonicalizeLinkageSet plaintext (`table=...`): the resulting member SET
    //     is in the bytes but the VERB is NOT (grant vs revoke are byte-identical),
    //     so render NEUTRAL "Role/membership assignment update" + the members.
    //   - CBOR AttestationUnit: structural `unit_type` only, no verb -> neutral
    //     type-specific title (existing behaviour).
    // Returns undefined only when nothing can be decoded, so the caller keeps the
    // neutral "Governance change" fallback. There is NO path that fabricates a grant.
    private _buildTitle(): string | undefined {
        // 1) NODE plaintext — true action present in signed bytes.
        const node = this._getNodeCanonical();
        if (node) {
            const titleFn = NODE_ACTION_TITLES[node.node];
            if (titleFn) return titleFn(this._nodeLabel(node));
            return `Governance change: ${node.node}`;
        }
        // 2) LINKAGE plaintext — set present, verb NOT present -> neutral.
        const linkage = this._getLinkageCanonical();
        if (linkage) {
            const owner = linkage.owners[0]?.owner;
            const ownerName = owner ? this._userName(owner) : undefined;
            if (ownerName && ownerName !== owner) return `Update the roles for user "${ownerName}"`;
            return "Update the roles for a user";
        }
        // 3) CBOR units — structural type only.
        const units = this._decodeUnits();
        const first = units[0];
        if (!first || typeof first !== "object") return undefined;

        const ut = first["unit_type"];
        const utName = (typeof ut === "number" && ATTESTATION_UNIT_TYPE_NAMES[ut] !== undefined)
            ? ATTESTATION_UNIT_TYPE_NAMES[ut]
            : (ut !== undefined ? String(ut) : undefined);

        if (utName === "user_role_mapping_set") {
            // user_role_mapping_set is a DECLARATIVE set (the user's full desired
            // role_ids), so the same unit type carries both grants AND revokes. We
            // CANNOT tell which from the bytes, so we must NOT say "Grant". Use
            // neutral "Role assignment update" wording, naming the target user when
            // the display-only context resolves it; the resulting role set is shown
            // in the details map, not asserted as a grant in the title.
            const payload = first["payload"];
            const userName = this._titleUserName(payload);
            if (userName) return `Update the roles for user "${userName}"`;
            return "Update the roles for a user";
        }

        // Any other attestation unit: give a readable, type-specific title that is
        // honest about the artifact type without asserting an action verb.
        if (utName) return `Approve change: ${utName.replace(/_/g, " ")}`;
        return undefined;
    }

    // User name for the title ONLY when the context resolved it to a username.
    private _titleUserName(payload: any): string | undefined {
        try {
            const userId = payload?.["user_id"];
            if (userId === undefined) return undefined;
            const name = this._context?.users?.[String(userId)];
            return (typeof name === "string" && name.length > 0) ? name : undefined;
        } catch { return undefined; }
    }

    // Resolve a role-id UUID to its friendly name via the display-only context,
    // falling back to the raw UUID when no name is available. Never throws.
    private _roleName(roleId: any): string {
        const id = String(roleId);
        try {
            const name = this._context?.roles?.[id];
            if (typeof name === "string" && name.length > 0) return name;
        } catch { /* fall through to id */ }
        return id;
    }

    // Resolve a user-id UUID to its username via the display-only context,
    // falling back to the raw UUID when no name is available. Never throws.
    private _userName(userId: any): string {
        const id = String(userId);
        try {
            const name = this._context?.users?.[id];
            if (typeof name === "string" && name.length > 0) return name;
        } catch { /* fall through to id */ }
        return id;
    }

    // Decode every attestation-unit envelope the draft carries. The draft is
    // AttestationUnitSignRequest framing: a TideMemory whose segment i is the
    // verbatim CBOR of unit i (req.SetUnits(byte[][]) on the producer). Never
    // throws - a malformed/absent unit is simply skipped.
    private _decodeUnits(): any[] {
        const units: any[] = [];
        if (!this._draft) return units;
        let res: any = {};
        for (let i = 0; TryGetValue(this._draft, i, res); i++) {
            const unitBytes = res.result;
            if (!unitBytes || unitBytes.length === 0) continue;
            try { units.push(decodeCbor(unitBytes)); } catch { /* skip undecodable unit */ }
        }
        return units;
    }

    // Decode the embedded admin Policy from the request's policy segment
    // (seg-9, req.SetPolicy(adminPolicyBytes)). Returns null when absent or
    // undecodable - never throws.
    private _decodePolicy(): Policy | null {
        try {
            const policyBytes = this.request?.policy;
            if (!policyBytes || policyBytes.length === 0) return null;
            return Policy.from(policyBytes);
        } catch { return null; }
    }

    // Pull a parameter from the Policy params map, tolerating missing keys.
    private _policyParam(policy: Policy | null, key: string): any {
        try {
            if (!policy || !policy.params) return undefined;
            const v = policy.params.entries.get(key);
            if (v instanceof Uint8Array) return undefined; // don't surface raw bytes
            return v;
        } catch { return undefined; }
    }

    // Find the human-friendly NAME of the realm this CR applies to, if a row
    // carries one. The signed rows usually carry only REALM_ID (a UUID/surrogate),
    // so a friendly realm name is shown only when REALM_NAME (or NAME on a REALM
    // node) is present. Returns undefined when no friendly name is available.
    private _realmName(node: ParsedNodeCanonical): string | undefined {
        for (const row of node.rows) {
            const v = row["REALM_NAME"];
            if (typeof v === "string" && v.length > 0) return v;
        }
        if (node.entityType === "REALM") {
            const lbl = this._nodeLabel(node);
            if (lbl && lbl !== "(unspecified)") return lbl;
        }
        return undefined;
    }

    // A single secondary "Technical id" value, when one is genuinely useful and not
    // already shown as a friendly name: prefer the entityId, else a noisy *_UUID/ID
    // row field. Returns undefined when there is nothing meaningful to tuck away.
    private _technicalId(node: ParsedNodeCanonical, primaryName: string | undefined): string | undefined {
        if (typeof node.entityId === "string" && node.entityId.length > 0
            && node.entityId !== "null" && node.entityId !== primaryName) {
            return node.entityId;
        }
        for (const row of node.rows) {
            for (const k of Object.keys(row)) {
                if (NODE_NOISY_FIELDS.has(k) && k !== "REALM_ID") {
                    const v = row[k];
                    if (typeof v === "string" && v.length > 0 && v !== primaryName) return v;
                }
            }
        }
        return undefined;
    }

    // Details for a canonicalizeNode plaintext draft (DELETE_*/DISABLE_IGA/...):
    // a small set of friendly, labelled fields stating exactly what the admin is
    // approving, plus a prominent plain-language consequence line for destructive
    // actions (reusing the enclave WARNING/severity convention). No raw row= blob,
    // no raw UUID surfaced as a primary field.
    private _nodeDetails(node: ParsedNodeCanonical, summary: any): void {
        // 1) Prominent destructive consequence line, styled by the enclave WARNING
        //    convention. Per-action wording when known, generic otherwise.
        if (NODE_DESTRUCTIVE_ACTIONS.has(node.node)) {
            summary["WARNING"] = NODE_DESTRUCTIVE_WARNINGS[node.node]
                ?? "Warning: this is a destructive governance action and may be unrecoverable.";
        }

        // 2) Plain "You are about to <verb>" line so the admin reads the intent in
        //    one sentence (falls back to the raw action only for unknown actions).
        summary["You are about to"] = NODE_ACTION_VERBS[node.node] ?? `Apply governance action: ${node.node}`;

        // 3) The primary friendly NAME of the artifact, under a plain noun label
        //    ("App"/"User"/"Role"/...). Falls back to the signed entityId only when
        //    no name is resolvable, so a missing name never blanks the card.
        const noun = (node.entityType && NODE_ENTITY_NOUNS[node.entityType]) || undefined;
        const primaryName = this._nodeLabel(node);
        const hasFriendly = primaryName && primaryName !== "(unspecified)";
        if (noun && hasFriendly) {
            summary[noun] = primaryName;
        } else if (hasFriendly && node.entityType !== "REALM") {
            summary["Name"] = primaryName;
        }

        // 4) The realm this applies to, by friendly name when present.
        const realm = this._realmName(node);
        if (realm) summary["Realm"] = realm;

        // 5) At most one secondary technical id, tucked away (never a primary field,
        //    never a row= blob). Omitted entirely when nothing useful remains.
        const tech = this._technicalId(node, hasFriendly ? primaryName : undefined);
        if (tech) summary["Technical id"] = tech;
    }

    // Details for a canonicalizeLinkageSet plaintext draft (role/group/composite
    // SET actions): the RESULTING member set per owner, names resolved via the
    // display-only context. The verb (grant vs revoke) is NOT in the signed bytes,
    // so we explicitly note that the resulting set is shown, not the operation.
    private _linkageDetails(linkage: ParsedLinkageCanonical, summary: any): void {
        const single = linkage.owners.length === 1;
        linkage.owners.forEach((o) => {
            const ownerName = this._userName(o.owner);
            const resolved = o.members.map((m) => {
                const r = this._roleName(m);
                return r !== m ? r : this._userName(m);
            });
            if (single) summary["For"] = ownerName;
            const label = single ? "Roles after this change" : `Roles after this change for ${ownerName}`;
            summary[label] = resolved.length > 0 ? resolved.join(", ") : "(none)";
        });
        summary["Note"] = "The system records the resulting set of roles. The signed approval does not record whether roles were added or removed.";
    }

    getDetailsMap(): any {
        const summary: any = {};
        try {
            // ---- producer plaintext canonical forms (true-action / neutral-set) -
            const node = this._getNodeCanonical();
            if (node) {
                this._nodeDetails(node, summary);
                this._appendTimingDetails(summary);
                return summary;
            }
            const linkage = this._getLinkageCanonical();
            if (linkage) {
                this._linkageDetails(linkage, summary);
                this._appendTimingDetails(summary);
                return summary;
            }

            // ---- CBOR AttestationUnit path (structural type, no verb) ----------
            const units = this._decodeUnits();
            const policy = this._decodePolicy();

            // ---- the action / unit being attested ------------------------------
            const first = units[0];
            if (first && typeof first === "object") {
                const ut = first["unit_type"];
                const utName = (typeof ut === "number" && ATTESTATION_UNIT_TYPE_NAMES[ut] !== undefined)
                    ? ATTESTATION_UNIT_TYPE_NAMES[ut]
                    : (ut !== undefined ? String(ut) : undefined);
                if (utName !== undefined) summary["Attestation Unit"] = utName;

                const payload = first["payload"];
                if (payload && typeof payload === "object") {
                    // Map UUIDs -> friendly names from the display-only context
                    // when available; fall back to the raw UUID otherwise so the
                    // admin reads "tide-realm-admin / alice" instead of two opaque
                    // UUIDs. The signed bytes still carry only UUIDs.
                    //
                    // NOTE: we surface the TARGET and the RESULTING role set under
                    // neutral, friendly labels ("User", "Roles after this change").
                    // We do NOT assert an action ("Grant role(s) to user"): the draft
                    // carries no action verb, and user_role_mapping_set is a
                    // declarative set that may be granting OR revoking. Showing the
                    // resulting set without a verb is the honest, provable rendering.
                    if (payload["user_id"] !== undefined) summary["User"] = this._userName(payload["user_id"]);
                    const roleIds = payload["role_ids"];
                    if (Array.isArray(roleIds) && roleIds.length > 0) {
                        summary["Roles after this change"] = roleIds.map((r: any) => this._roleName(r)).join(", ");
                        summary["Note"] = "The system records the resulting set of roles. The signed approval does not record whether roles were added or removed.";
                    }
                }
                if (first["target_id"] !== undefined && summary["User"] === undefined) {
                    summary["Technical id"] = String(first["target_id"]);
                }
            }
            if (units.length > 1) summary["Units In Request"] = units.length;

            // ---- the governing admin Policy ------------------------------------
            if (policy) {
                const role = this._policyParam(policy, "role");
                if (role !== undefined) summary["Governing Policy Role"] = String(role);
                const resource = this._policyParam(policy, "resource");
                if (resource !== undefined) summary["Resource"] = String(resource);
                const threshold = this._policyParam(policy, "threshold");
                if (threshold !== undefined) summary["Approvals Required"] = threshold;
            }

            // ---- timing (also surfaced by the enclave chrome; included here for
            //      a self-contained card, guarded so it never throws) ------------
            this._appendTimingDetails(summary);
        } catch { /* never throw from the summary builder */ }
        return summary;
    }

    // Append the request expiry / requested-at lines, each individually guarded so
    // a missing/uninitialized field never throws out of the summary builder.
    private _appendTimingDetails(summary: any): void {
        try {
            if (this.request && typeof this.request.expiry === "number") {
                summary["Expires"] = new Date(this.request.expiry * 1000).toUTCString();
            }
        } catch { /* expiry not readable */ }
        try {
            if (this.request && this.request.isInitialized()) {
                summary["Requested At"] = new Date(this.request.getInitializedTime() * 1000).toUTCString();
            }
        } catch { /* not initialized */ }
    }

    getRequestDataJson(): any {
        const data: any = {};
        try {
            // Producer plaintext canonical forms render their parsed structure
            // (the raw JSON view mirrors the accurate-vs-neutral details split).
            const node = this._getNodeCanonical();
            if (node) {
                data["node"] = { action: node.node, entityType: node.entityType, entityId: node.entityId, rows: node.rows };
                return data;
            }
            const linkage = this._getLinkageCanonical();
            if (linkage) {
                data["linkageSet"] = { table: linkage.table, owners: linkage.owners };
                return data;
            }

            const units = this._decodeUnits();
            // Render bytes as hex so the JSON view is clean (decodeCbor only yields
            // Uint8Array for CBOR byte-strings, which the unit payloads don't use,
            // but guard anyway).
            data["units"] = units.map((u) => this._jsonSafe(u));

            const policy = this._decodePolicy();
            if (policy) {
                const role = this._policyParam(policy, "role");
                const resource = this._policyParam(policy, "resource");
                const threshold = this._policyParam(policy, "threshold");
                const p: any = {};
                if (role !== undefined) p.role = role;
                if (resource !== undefined) p.resource = resource;
                if (threshold !== undefined) p.threshold = threshold;
                data["policy"] = p;
            }
        } catch { /* never throw */ }
        return data;
    }

    // Recursively replace Uint8Array with hex strings so JSON.stringify in the
    // enclave produces a readable view.
    private _jsonSafe(v: any): any {
        if (v instanceof Uint8Array) return Bytes2Hex(v);
        if (Array.isArray(v)) return v.map((x) => this._jsonSafe(x));
        if (v && typeof v === "object") {
            const out: any = {};
            for (const k of Object.keys(v)) out[k] = this._jsonSafe(v[k]);
            return out;
        }
        return v;
    }

    // NOTE: getDataToApprove() is intentionally NOT overridden. The enclave signs
    // exactly what the base HumanReadableModelBuilder returns (this.request
    // .dataToApprove()), identical to PolicySignRequestBuilder and every other
    // approval builder, so SessionKey.sign(getDataToApprove()) + addApproval
    // produce a valid approval.
}

const modelBuildersMap = {
    [new OffboardSignRequestBuilder(null as any, null as any)._id]: OffboardSignRequestBuilder,
    [new LicenseSignRequestBuilder(null as any, null as any)._id]: LicenseSignRequestBuilder,
    [new TestInitSignRequestBuilder(null as any, null as any)._id]: TestInitSignRequestBuilder,
    [new PolicySignRequestBuilder(null as any, null as any)._id]: PolicySignRequestBuilder,
    [new HederaSignRequestBuilder(null as any, null as any)._id]: HederaSignRequestBuilder,
    [new PolicyEnabledEncryptionRequestBuilder(null as any, null as any)._id]: PolicyEnabledEncryptionRequestBuilder,
    [new PolicyEnabledDecryptionRequestBuilder(null as any, null as any)._id]: PolicyEnabledDecryptionRequestBuilder,
    [new ServerCertSignRequestBuilder(null as any, null as any)._id]: ServerCertSignRequestBuilder,
    [new AttestationUnitSignRequestBuilder(null as any, null as any)._id]: AttestationUnitSignRequestBuilder,
}