"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OffboardSignRequestBuilder = exports.HumanReadableModelBuilder = exports.ModelRegistry = void 0;
const Serialization_1 = require("../Cryptide/Serialization");
const BaseTideRequest_1 = __importDefault(require("./BaseTideRequest"));
// @ts-ignore
const asgard_tide_1 = require("asgard-tide");
const index_1 = require("../Cryptide/index");
class ModelRegistry {
    /**
     * @returns {HumanReadableModelBuilder}
     */
    static getHumanReadableModelBuilder(reqId, data) {
        const r = BaseTideRequest_1.default.decode(data);
        const nameMatch = r.name.match(/^Custom<(.*)>$/)?.[1];
        const versionMatch = r.version.match(/^Custom<(.*)>$/)?.[1];
        if (nameMatch && versionMatch) {
            return new CustomSignRequestBuilder(data, reqId);
        }
        const c = modelBuildersMap[r.id()];
        if (!c)
            throw Error("Could not find model: " + r.id());
        return c.create(data, reqId);
    }
}
exports.ModelRegistry = ModelRegistry;
class HumanReadableModelBuilder {
    constructor(data, reqId) {
        this._humanReadableName = null;
        if (data) {
            this._data = data;
            this._draft = (0, Serialization_1.GetValue)(this._data, 3);
            this.request = BaseTideRequest_1.default.decode(data);
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
exports.HumanReadableModelBuilder = HumanReadableModelBuilder;
// MODELS ----------------------------------------------------------------
class CustomSignRequestBuilder extends HumanReadableModelBuilder {
    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId) {
        super(data, reqId);
        this._name = this.request.name.match(/^Custom<(.*)>$/)?.[1];
        this._version = this.request.version.match(/^Custom<(.*)>$/)?.[1];
        this.humanReadableJson = JSON.parse((0, Serialization_1.StringFromUint8Array)((0, Serialization_1.GetValue)(this.request.draft, 0)));
        this._humanReadableName = this.humanReadableJson["humanReadableName"];
    }
    getRequestDataJson() {
        return this.humanReadableJson["additionalInfo"];
    }
}
// Need this while we work on better custom models
class HederaSignRequestBuilder extends HumanReadableModelBuilder {
    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId) {
        super(data, reqId);
        this._name = "HederaTx";
        this._version = "1";
        if (data) {
            this.customInfo = JSON.parse((0, Serialization_1.StringFromUint8Array)(index_1.Serialization.GetValue(this.request.draft, 0)));
            this.additionalInfo = this.customInfo["additionalInfo"];
            this._humanReadableName = `Request to send ${BigInt(this.additionalInfo["Total being spent (tinybar)"]) / BigInt(100000000)} HBAR`;
        }
    }
    getRequestDataJson() {
        return this.additionalInfo;
    }
}
class UserContextSignRequestBuilder extends HumanReadableModelBuilder {
    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId) {
        super(data, reqId);
        this._name = "UserContext"; // Model ID
        this._humanReadableName = "User Access Change";
        this._version = "1";
    }
    static create(data, reqId) {
        return super.create(data, reqId);
    }
    getRequestDataJson() {
        // deserialize draft here and return a pretty object for user
        let prettyObject = {};
        let draftIndex = 0;
        // make sure user context is JSON
        let cont = true;
        prettyObject.UserContexts = [];
        while (cont) {
            try {
                prettyObject.UserContexts.push(JSON.parse((0, Serialization_1.StringFromUint8Array)((0, Serialization_1.GetValue)(this._draft, draftIndex))));
                draftIndex++;
            }
            catch {
                cont = false;
            }
        }
        // return a nice object of InitCert? and usercontexts
        return prettyObject;
    }
    getDetailsMap() {
        // deserialize draft here and return a pretty object for user
        let prettyObject = {};
        let draftIndex = 0;
        // make sure user context is JSON
        let cont = true;
        prettyObject.UserContexts = [];
        while (cont) {
            try {
                prettyObject.UserContexts.push(JSON.parse((0, Serialization_1.StringFromUint8Array)((0, Serialization_1.GetValue)(this._draft, draftIndex))));
                draftIndex++;
            }
            catch {
                cont = false;
            }
        }
        // Create summary
        let summary = {};
        // Get the clients involved in this approval
        // All clients will be either realm-management or under resource_management
        let clients = [];
        prettyObject.UserContexts.map(c => {
            if (c.realm_access)
                clients.push("realm_access");
            if (typeof c.resource_access === "object") {
                clients.push(...Object.keys(c.resource_access));
            }
        });
        clients = [...new Set(clients)];
        summary["Applications affected"] = clients.join(", ");
        // return a nice object of InitCert? and usercontexts
        return summary;
    }
}
class OffboardSignRequestBuilder extends HumanReadableModelBuilder {
    get _id() { return this._name + ":" + this._version; }
    constructor(data, reqId) {
        super(data, reqId);
        this._name = "Offboard";
        this._version = "1";
        this._humanReadableName = "Cancel Tide Subscription and Protection";
    }
    getDetailsMap() {
        let summary = {};
        summary["WARNING WARNING WARNING"] = "";
        summary["APPROVING THIS REQUEST WILL CRIPPLE YOUR LICENSED TIDE ACCOUNT"] = "";
        summary["ONLY APPROVE THIS REQUEST IF YOU INTEND TO OFFBOARD FROM THE TIDE NETWORK"] = "";
        summary["THIS ACTION IS UNRECOVERABLE"] = "";
        return summary;
    }
    getRequestDataJson() {
        const vrk = (0, Serialization_1.Bytes2Hex)((0, Serialization_1.GetValue)(this._draft, 0));
        let body = {
            "Vendor Rotating Key for Offboarding": vrk
        };
        return body;
    }
}
exports.OffboardSignRequestBuilder = OffboardSignRequestBuilder;
class PolicySignRequestBuilder extends HumanReadableModelBuilder {
    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry) {
        super(data, expiry);
        this._name = "Policy";
        this._version = "1";
        this._humanReadableName = "Approve new policy for use with Tide";
    }
    getDetailsMap() {
        let summary = {};
        const draftBytes = this._draft;
        if (!draftBytes)
            return { error: 'No draft data' };
        const policyBytes = (0, Serialization_1.GetValue)(draftBytes, 0);
        const policy = asgard_tide_1.Policy.from(policyBytes);
        summary['Version'] = policy.version;
        summary['ContractId'] = policy.contractId;
        summary['ModelId'] = policy.modelId;
        summary["KeyId"] = policy.keyId;
        summary['Approval Type'] = asgard_tide_1.ApprovalType[policy.approvalType];
        summary["Execution Type"] = asgard_tide_1.ExecutionType[policy.executionType];
        policy.params.entries.entries().forEach(([key, value]) => {
            if (!(value instanceof Uint8Array))
                summary[`Parameter:${key}`] = value;
        });
        let res = {};
        if ((0, Serialization_1.TryGetValue)(draftBytes, 1, res)) {
            const contractBytes = res.result;
            const contractType = (0, Serialization_1.StringFromUint8Array)((0, Serialization_1.GetValue)(contractBytes, 0));
            summary["Contract To Upload Type"] = contractType;
            summary["Contract Included"] = "Yes - see Request Data for source code";
        }
        return summary;
    }
    getRequestDataJson() {
        let data = {};
        const draftBytes = this._draft;
        if (!draftBytes)
            return data;
        // Only show contract source code - other info is in the summary
        // Structure: draft[1] = contractTransport = ["forseti", forsetiData]
        // forsetiData = [placeholder, innerPayload]
        // innerPayload = [sourceCode, entryType?]
        let res = {};
        if ((0, Serialization_1.TryGetValue)(draftBytes, 1, res)) {
            const contractBytes = res.result;
            // contractBytes[1] = forsetiData
            let forsetiDataRes = {};
            if ((0, Serialization_1.TryGetValue)(contractBytes, 1, forsetiDataRes)) {
                const forsetiData = forsetiDataRes.result;
                // forsetiData[1] = innerPayload
                let innerPayloadRes = {};
                if ((0, Serialization_1.TryGetValue)(forsetiData, 1, innerPayloadRes)) {
                    const innerPayload = innerPayloadRes.result;
                    // innerPayload[0] = sourceCode
                    let sourceCodeRes = {};
                    if ((0, Serialization_1.TryGetValue)(innerPayload, 0, sourceCodeRes)) {
                        const contractCode = (0, Serialization_1.StringFromUint8Array)(sourceCodeRes.result);
                        data["Contract Source Code"] = contractCode;
                    }
                }
            }
        }
        return data;
    }
}
class LicenseSignRequestBuilder extends HumanReadableModelBuilder {
    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry) {
        super(data, expiry);
        this._name = "RotateVRK";
        this._version = "1";
        this._humanReadableName = "Renew License with New Permissions";
    }
    getDetailsMap() {
        const authPack = new Serialization_1.AuthorizerPack(this._draft);
        let summary = [];
        summary["Signing new license"] = authPack.Authorizer.GVRK.Serialize().ToString();
        summary["Approved Models to Sign"] = authPack.SignModels;
        return summary;
    }
}
class TestInitSignRequestBuilder extends HumanReadableModelBuilder {
    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry) {
        super(data, expiry);
        this._name = "TestInit";
        this._version = "1";
        this._humanReadableName = "Test Tide Request";
    }
    getDetailsMap() {
        let summary = [];
        summary["Draft Detail"] = (0, Serialization_1.StringFromUint8Array)(this._draft);
        return summary;
    }
}
const modelBuildersMap = {
    [new UserContextSignRequestBuilder(null, null)._id]: UserContextSignRequestBuilder,
    [new OffboardSignRequestBuilder(null, null)._id]: OffboardSignRequestBuilder,
    [new LicenseSignRequestBuilder(null, null)._id]: LicenseSignRequestBuilder,
    [new TestInitSignRequestBuilder(null, null)._id]: TestInitSignRequestBuilder,
    [new PolicySignRequestBuilder(null, null)._id]: PolicySignRequestBuilder,
    [new HederaSignRequestBuilder(null, null)._id]: HederaSignRequestBuilder
};
