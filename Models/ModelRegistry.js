import { AuthorizerPack, Bytes2Hex, bytesToBase64, GetValue, StringFromUint8Array, TryGetValue } from "../Cryptide/Serialization.js";
import InitializationCertificate from "./InitializationCertificate.js";
import RuleSettings from "./Rules/RuleSettings.js";
import CardanoTxBody from "./Cardano/CardanoTxBody.js";
import BaseTideRequest from "./BaseTideRequest.js";
import { Policy } from "asgard-tide";
import { Serialization } from "../Cryptide/index.js";

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
        let prettyObject = {};

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
    getDetailsMap() {
        // deserialize draft here and return a pretty object for user
        let prettyObject = {};

        let draftIndex = 0;
        // make sure user context is JSON
        let cont = true;
        prettyObject.UserContexts = [];
        while (cont) {
            try { prettyObject.UserContexts.push(JSON.parse(StringFromUint8Array(GetValue(this._draft, draftIndex)))); draftIndex++; }
            catch { cont = false; }
        }

        // Create summary
        let summary = {};
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
    getDetailsMap() {
        let summary = {};
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

    getDetailsMap() {
        let summary = {};

        const draftBytes = this._draft;
        if (!draftBytes) return { error: 'No draft data' };

        const policyBytes = GetValue(draftBytes, 0);
        const policy = Policy.from(policyBytes);

        summary['Version'] = policy.version;
        summary['ContractId'] = policy.contractId;
        summary['ModelId'] = policy.modelId;
        summary["KeyId"] = policy.keyId;
        summary['Approval Type'] = policy.approvalType.toString();
        summary["Execution Type"] = policy.executionType.toString();
        
        policy.params.entries().forEach(([key, value]) => {
            if (!(value instanceof Uint8Array)) summary[`Parameter:${key}`] = value;
        });

        let res = {};
        if (TryGetValue(draftBytes, 1, res)) {
            const contractBytes = res.result;
            const contractType = StringFromUint8Array(GetValue(contractBytes, 0));
            summary["Contract To Upload Type"] = contractType;
            summary["Contract Included"] = "Yes - see Request Data for source code";
        }
        return summary;
    }

    getRequestDataJson() {
        let data = {};

        const draftBytes = this._draft;
        if (!draftBytes) return data;

        // Only show contract source code - other info is in the summary
        // Structure: draft[1] = contractTransport = ["forseti", forsetiData]
        // forsetiData = [placeholder, innerPayload]
        // innerPayload = [sourceCode, entryType?]
        let res = {};
        if (TryGetValue(draftBytes, 1, res)) {
            const contractBytes = res.result;

            // contractBytes[1] = forsetiData
            let forsetiDataRes = {};
            if (TryGetValue(contractBytes, 1, forsetiDataRes)) {
                const forsetiData = forsetiDataRes.result;

                // forsetiData[1] = innerPayload
                let innerPayloadRes = {};
                if (TryGetValue(forsetiData, 1, innerPayloadRes)) {
                    const innerPayload = innerPayloadRes.result;

                    // innerPayload[0] = sourceCode
                    let sourceCodeRes = {};
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

        let summary = [];
        summary["Signing new license"] = authPack.Authorizer.GVRK.Serialize().ToString();

        summary["Approved Models to Sign"] = authPack.SignModels;

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
        let summary = [];
        summary["Draft Detail"] = StringFromUint8Array(this._draft);
        return summary;
    }
}

const modelBuildersMap = {
    [new UserContextSignRequestBuilder()._id]: UserContextSignRequestBuilder,
    [new OffboardSignRequestBuilder()._id]: OffboardSignRequestBuilder,
    [new LicenseSignRequestBuilder()._id]: LicenseSignRequestBuilder,
    [new TestInitSignRequestBuilder()._id]: TestInitSignRequestBuilder,
    [new PolicySignRequestBuilder()._id]: PolicySignRequestBuilder,
    [new HederaSignRequestBuilder()._id]: HederaSignRequestBuilder
}