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
    /**
     * @returns {HumanReadableModelBuilder}
     */
    static getHumanReadableModelBuilder(reqId, data) {
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
        summary['ModelId'] = policy.modelId;
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

const modelBuildersMap = {
    [new UserContextSignRequestBuilder(null as any, null as any)._id]: UserContextSignRequestBuilder,
    [new OffboardSignRequestBuilder(null as any, null as any)._id]: OffboardSignRequestBuilder,
    [new LicenseSignRequestBuilder(null as any, null as any)._id]: LicenseSignRequestBuilder,
    [new TestInitSignRequestBuilder(null as any, null as any)._id]: TestInitSignRequestBuilder,
    [new PolicySignRequestBuilder(null as any, null as any)._id]: PolicySignRequestBuilder,
    [new HederaSignRequestBuilder(null as any, null as any)._id]: HederaSignRequestBuilder
}