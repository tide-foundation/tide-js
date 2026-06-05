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

export class ModelRegistry {
    static getHumanReadableModelBuilder(reqId: string, data: Uint8Array): HumanReadableModelBuilder {
        const r = BaseTideRequest.decode(data);
        const nameMatch = r.name.match(/^Custom<(.*)>$/)?.[1];
        const versionMatch = r.version.match(/^Custom<(.*)>$/)?.[1];
        if (nameMatch && versionMatch) {
            return new CustomSignRequestBuilder(data, reqId);
        }
        const c = modelBuildersMap[r.id()];
        if (!c) throw Error("Could not find model: " + r.id());
        return c.create(data, reqId);
    }
}

export class HumanReadableModelBuilder {
    _humanReadableName = null;
    _data: any;
    _draft: any;
    request: BaseTideRequest | undefined;
    reqId: any;
    constructor(data, reqId) {
        if (data) {
            this._data = data;
            this._draft = GetValue(this._data, 3);
            this.request = BaseTideRequest.decode(data);
        }
        this.reqId = reqId;
    }
    static create(data, reqId) {
        return new this(data, reqId);
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
    constructor(data, reqId) {
        super(data, reqId);
        this._name = this.request.name.match(/^Custom<(.*)>$/)?.[1];
        this._version = this.request.version.match(/^Custom<(.*)>$/)?.[1];
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
class UserContextSignRequestBuilder extends HumanReadableModelBuilder {
    _name = "UserContext"; // Model ID
    _humanReadableName = "User Access Change";
    _version = "1";
    get _id() { return this._name + ":" + this._version; }

    constructor(data, reqId) {
        super(data, reqId);
    }
    static create(data, reqId) {
        return super.create(data, reqId);
    }
    getRequestDataJson() {
        // deserialize draft here and return a pretty object for user
        let prettyObject: any = {};

        let draftIndex = 0;
        // make sure user context is JSON
        let cont = true;
        prettyObject.UserContexts = [];
        while (cont) {
            try { prettyObject.UserContexts.push(JSON.parse(StringFromUint8Array(GetValue(this._draft, draftIndex)))); draftIndex++; }
            catch { cont = false; }
        }

        // return a nice object of InitCert? and usercontexts
        return prettyObject;
    }
    getDetailsMap(): any {
        // deserialize draft here and return a pretty object for user
        let prettyObject: any = {};

        let draftIndex = 0;
        // make sure user context is JSON
        let cont = true;
        prettyObject.UserContexts = [];
        while (cont) {
            try { prettyObject.UserContexts.push(JSON.parse(StringFromUint8Array(GetValue(this._draft, draftIndex)))); draftIndex++; }
            catch { cont = false; }
        }

        // Create summary
        let summary: any = {};
        // Get the clients involved in this approval
        // All clients will be either realm-management or under resource_management
        let clients = [];
        prettyObject.UserContexts.map(c => {
            if (c.realm_access) clients.push("realm_access");
            if (typeof c.resource_access === "object") {
                clients.push(...Object.keys(c.resource_access));
            }
        })
        clients = [...new Set(clients)];
        summary["Applications affected"] = clients.join(", ");

        // return a nice object of InitCert? and usercontexts
        return summary;
    }
}

export class OffboardSignRequestBuilder extends HumanReadableModelBuilder {
    _name = "Offboard";
    _version = "1";
    _humanReadableName = "Cancel Tide Subscription and Protection";

    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId) {
        super(data, reqId);
    }
    getDetailsMap(): any {
        let summary: any = {};
        summary["WARNING WARNING WARNING"] = "";
        summary["APPROVING THIS REQUEST WILL CRIPPLE YOUR LICENSED TIDE ACCOUNT"] = "";
        summary["ONLY APPROVE THIS REQUEST IF YOU INTEND TO OFFBOARD FROM THE TIDE NETWORK"] = "";
        summary["THIS ACTION IS UNRECOVERABLE"] = "";


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
    }

    getDetailsMap(): any {
        let summary: any = {};

        const draftBytes = this._draft;
        if (!draftBytes) return { error: 'No draft data' };

        const policyBytes = GetValue(draftBytes, 0);
        const policy = Policy.from(policyBytes);

        summary['Version'] = policy.version;
        summary['ContractId'] = policy.contractId;
        summary['ModelId'] = policy.modelIds.join(", ");
        summary["KeyId"] = policy.keyId;
        summary['Approval Type'] = ApprovalType[policy.approvalType];
        summary["Execution Type"] = ExecutionType[policy.executionType];
        for (const [key, value] of policy.params.entries.entries()) {
            if (!(value instanceof Uint8Array)) summary[`Parameter:${key}`] = value;
        }

        let res: any = {};
        if (TryGetValue(draftBytes, 1, res)) {
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
        if (TryGetValue(draftBytes, 1, res)) {
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
// producer side — see RealmAttestationExporter / AttestationUnit.java). tide-js
// has no CBOR dependency, so we decode the small, well-defined subset Jackson
// emits here: unsigned/negative integers, byte/text strings, arrays, maps and
// the simple values false/true/null — definite AND indefinite length. This is
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
                    // half/single/double float — not used by the unit envelopes; skip bytes.
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

class AttestationUnitSignRequestBuilder extends HumanReadableModelBuilder {
    _name = "AttestationUnit";
    _version = "1";
    _humanReadableName = "Approve Attestation — Role Assignment";
    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId) {
        super(data, reqId);
    }

    // Decode every attestation-unit envelope the draft carries. The draft is
    // AttestationUnitSignRequest framing: a TideMemory whose segment i is the
    // verbatim CBOR of unit i (req.SetUnits(byte[][]) on the producer). Never
    // throws — a malformed/absent unit is simply skipped.
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
    // undecodable — never throws.
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

    getDetailsMap(): any {
        const summary: any = {};
        try {
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
                if (utName === "user_role_mapping_set") summary["Action"] = "Grant role(s) to user";

                const payload = first["payload"];
                if (payload && typeof payload === "object") {
                    if (payload["user_id"] !== undefined) summary["Target User"] = String(payload["user_id"]);
                    const roleIds = payload["role_ids"];
                    if (Array.isArray(roleIds) && roleIds.length > 0) {
                        summary["Roles"] = roleIds.map((r: any) => String(r)).join(", ");
                    }
                }
                if (first["target_id"] !== undefined && summary["Target User"] === undefined) {
                    summary["Target"] = String(first["target_id"]);
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
        } catch { /* never throw from the summary builder */ }
        return summary;
    }

    getRequestDataJson(): any {
        const data: any = {};
        try {
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
    [new UserContextSignRequestBuilder(null as any, null as any)._id]: UserContextSignRequestBuilder,
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