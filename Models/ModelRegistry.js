import { AuthorizerPack, Bytes2Hex, bytesToBase64, GetValue, StringFromUint8Array, TryGetValue } from "../Cryptide/Serialization.js";
import InitializationCertificate from "./InitializationCertificate.js";
import RuleSettings from "./Rules/RuleSettings.js";
import CardanoTxBody from "./Cardano/CardanoTxBody.js";
import BaseTideRequest from "./BaseTideRequest.js";
import Policy from "./Policy.js";

export class ModelRegistry{
    /**
     * @returns {HumanReadableModelBuilder}
     */
    static getHumanReadableModelBuilder(reqId, data){
        const r = BaseTideRequest.decode(data);
        const c = modelBuildersMap[r.id()];
        if(!c) throw Error("Could not find model: " + r.id());
        return c.create(data, reqId);
    }
}

export class HumanReadableModelBuilder{
    _humanReadableName = null;
    constructor(data, reqId){
        if(data){
            this._data = data;
            this.request = BaseTideRequest.decode(data);
        }
        this.reqId = reqId;
    }
    static create(data, reqId){
        return new this(data, reqId);
    }
    async getRequestId(){
        // hash of the request
        return Bytes2Hex(await this.request.dataToAuthorize());
    }
    getApprovalRecieved(){
        // how many approvals have been already submitted for this model
        const authorizers = GetValue(this._data, 6);
        let i = 0;
        while(TryGetValue(authorizers, i, _)){i++;}
        return i;
    }
    getApprovalsRequired(){
        const policy = new Policy(GetValue(this._data, 9));


        // Ok so in the future we'll want to support multi-role multi-threshold approvals
        // but since the the UI doesn't support it and we don't even have a contract yet to support it
        // we'll implement the logic later
        // for now we'll only be supporting on role/threshold

        return policy.params.getParameter("threshold", String);
    }
    getDetailsMap(){
        // the summary
        throw Error("Not implemented for this model");
    }
    getRequestDataJson(){
        // raw json
        throw Error("Not implemented for this model");
    }

    getExpiry(){
        return this.request.expiry;
    }
}

// MODELS ----------------------------------------------------------------
class UserContextSignRequestBuilder extends HumanReadableModelBuilder{
    _name = "UserContext"; // Model ID
    _humanReadableName = "User Access Change";
    _version = "1";
    get _id() { return this._name + ":" + this._version; }

    constructor(data, expiry){
        super(data, expiry);
    }
    static create(data, expiry){
        return super.create(data, expiry);
    }
    getHumanReadableObject(){
        // deserialize draft here and return a pretty object for user
        let prettyObject = {};

        let draftIndex = 0;
        const initCertPresent = GetValue(this._data, 0)[0];
        draftIndex++;

        // determine if InitCert is present
        switch(initCertPresent){
            case 0:
                break;
            case 1:
                const initCert = GetValue(this._data, draftIndex);
                prettyObject.InitializationCertificate = new InitializationCertificate(StringFromUint8Array(initCert)).toPrettyObject();
                draftIndex++;
                break;
            default:
                throw Error("Unexpected value");
        }
        // make sure user context is JSON
        let cont = true;
        prettyObject.UserContexts = [];
        while(cont){
            try{prettyObject.UserContexts.push(JSON.parse(StringFromUint8Array(GetValue(this._data, draftIndex))));draftIndex++;}
            catch{cont = false;}
        }

        // Create summary
        let summary = [];
        summary.push(["Admin related", initCertPresent == 1 ? "YES" : "no"]);
        // Get the clients involved in this approval
        // All clients will be either realm-management or under resource_management
        let clients = [];
        prettyObject.UserContexts.map(c => {
            if(c.realm_access) clients.push("realm_access");
            if(typeof c.resource_access === "object"){
                clients.push(...Object.keys(c.resource_access));
            }
        })
        clients = [...new Set(clients)];
        summary.push(["Applications affected", clients.join(", ")]);
        summary.push(["Expiry", unixSecondsToLocaleString(this._expiry)])
        
        // return a nice object of InitCert? and usercontexts
        return {
            summary: summary,
            pretty: prettyObject
        }
    }
}
class CardanoTxSignRequestBuilder extends HumanReadableModelBuilder{ // this is an example class
    _name = "CardanoTx"; // Model ID
    _humanReadableName = "Send Cardano Funds";
    _version = "1";
    get _id() { return this._name + ":" + this._version; }

    constructor(data, expiry){
        //throw Error("Not implemented");
        super(data, expiry);
    }
    getHumanReadableObject(){
        // deserialize draft here and return a pretty object for user
        const txBytes = GetValue(this._data, 0);
        const body = new CardanoTxBody(txBytes);

        let summary = [];
        body.transaction.outputs.map(o => {
            summary.push([`Outgoing ada to ${o.address}`, (o.amount / 1_000_000n).toString()]);
        })
        summary.push(["Fee", body.transaction.fee.toString()])

        return {
            summary: summary,
            pretty: body.toPrettyObject()
        }
    }
}

class OffboardSignRequestBuilder extends HumanReadableModelBuilder{
    _name = "Offboard";
    _version = "1";
    _humanReadableName = "Cancel Tide Subscription and Protection";

    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry){
        super(data, expiry);
    }
    getHumanReadableObject(){
        let summary = [];
        summary.push(["WARNING WARNING WARNING", ""]);
        summary.push(["APPROVING THIS REQUEST WILL CRIPPLE YOUR LICENSED TIDE ACCOUNT", ""]);
        summary.push(["ONLY APPROVE THIS REQUEST IF YOU INTEND TO OFFBOARD FROM THE TIDE NETWORK", ""]);
        summary.push(["THIS ACTION IS UNRECOVERABLE", ""]);

        const vrk = Bytes2Hex(GetValue(this._data, 0));
        let body = {
            "Vendor Rotating Key for Offboarding": vrk
        }
        return {
            summary: summary,
            pretty: body
        }
    }
}

class LicenseSignRequestBuilder extends HumanReadableModelBuilder{
    _name = "RotateVRK";
    _version = "1";
    _humanReadableName = "Rotating VRK";

    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry){
        super(data, expiry);
    }
    getHumanReadableObject(){
        const authPack = new AuthorizerPack(this._data);

        let summary = [];
        summary.push(["Signing new license", authPack.Authorizer.GVRK.Serialize().ToString()]);

        let body = {
            "AuthFlow": authPack.AuthFlow,
            "Authorizer": authPack.Authorizer.GVRK.Serialize().ToString(),
            "SignModels": authPack.SignModels
        }
        return {
            summary: summary,
            pretty: body
        }
    }
}

const modelBuildersMap = {
    [new UserContextSignRequestBuilder()._id]: UserContextSignRequestBuilder,
    [new CardanoTxSignRequestBuilder()._id]: CardanoTxSignRequestBuilder,
    [new OffboardSignRequestBuilder()._id]: OffboardSignRequestBuilder,
    [new LicenseSignRequestBuilder()._id]: LicenseSignRequestBuilder
}

const unixSecondsToLocaleString = (unixSeconds) => {
  const milliseconds = unixSeconds * 1000;
  const date = new Date(milliseconds);

  return date.toLocaleString('en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  });
};