import { Bytes2Hex, GetValue, StringFromUint8Array } from "../Cryptide/Serialization.js";
import InitializationCertificate from "./InitializationCertificate.js";
import RuleSettings from "./Rules/RuleSettings.js";
import CardanoTxBody from "./Cardano/CardanoTxBody.js";

export class ModelRegistry{
    /**
     * 
     * @param {string} modelId 
     * @returns {HumanReadableModelBuilder}
     */
    static getHumanReadableModelBuilder(modelId, data, expiry){
        const c = modelBuildersMap[modelId];
        if(!c) throw Error("Could not find model: " + modelId);
        return c.create(data, expiry);
    }
}

export class HumanReadableModelBuilder{
    constructor(data, expiry){
        this._data = data;
        this._expiry = expiry;
    }
    static create(data, expiry){
        return new this(data, expiry);
    }
    getHumanReadableObject(){
        throw Error("Not implemented for this model");
    }
}

// MODELS ----------------------------------------------------------------
class UserContextSignRequestBuilder extends HumanReadableModelBuilder{
    _name = "UserContext"; // Model ID
    _humanReadableName = "Change Request";
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

class RuleSettingSignRequestBuilder extends HumanReadableModelBuilder{ // this is an example class
    _name = "Rules"; // Model ID
    _version = "1";
    get _id() { return this._name + ":" + this._version; }

    constructor(data, expiry){
        //throw Error("Not implemented");
        super(data, expiry);
    }
    getHumanReadableObject(){
        // deserialize draft here and return a pretty object for user
        let prettyObject = {};

        let draftIndex = 0;
        const previousRulesPresent = GetValue(this._data, 0)[0];
        draftIndex++;

        // determine if InitCert is present
        switch(previousRulesPresent){
            case 0:
                break;
            case 1:
                const previousRuleSettings = GetValue(this._data, draftIndex);
                prettyObject.RuleSettingToRevoke = new RuleSettings(StringFromUint8Array(previousRuleSettings)).toPrettyObject();
                draftIndex += 2;
                break;
            default:
                throw Error("Unexpected value");
        }

        const newRuleSettings = GetValue(this._data, draftIndex);
        prettyObject.NewRuleSetting = new RuleSettings(StringFromUint8Array(newRuleSettings)).toPrettyObject(); 
        return {
            summary: [["No summary for RuleSettings"]],
            pretty: prettyObject
        }
    }
}

class OffboardSignRequestBuilder extends HumanReadableModelBuilder{
    _name = "Offboard";
    _version = "1";
    _humanReadableName = "Tide Offboarding";

    get _id() { return this._name + ":" + this._version; }
    constructor(data, expiry){
        //throw Error("Not implemented");
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

const modelBuildersMap = {
    [new UserContextSignRequestBuilder()._id]: UserContextSignRequestBuilder,
    [new CardanoTxSignRequestBuilder()._id]: CardanoTxSignRequestBuilder,
    [new RuleSettingSignRequestBuilder()._id]: RuleSettingSignRequestBuilder,
    [new OffboardSignRequestBuilder()._id]: OffboardSignRequestBuilder
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