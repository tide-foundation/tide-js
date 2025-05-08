import { GetValue, StringFromUint8Array } from "../Cryptide/Serialization.js";
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
    static _name = "UserContext";
    static _version = "1";
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
        summary.push(["Creating new admin group", initCertPresent == 1 ? "YES" : "no"]);
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
        if(clients.length > 5){
            for (let i = 0; i < clients.length; i += 5) {
                const chunk = clients.slice(i, i + 5);
                summary.push([`Clients involved [${i}]`, chunk.join(", ")]);
              }
        }else{
            summary.push(["Clients involved", clients.join(", ")]);
        }

        // return a nice object of InitCert? and usercontexts
        return {
            summary: summary,
            pretty: prettyObject
        }
    }
}
class CardanoTxSignRequestBuilder extends HumanReadableModelBuilder{ // this is an example class
    static _name = "CardanoTx";
    static _version = "1";
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
    static _name = "Rules";
    static _version = "1";
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

const modelBuildersMap = {
    [UserContextSignRequestBuilder._name + ":" + UserContextSignRequestBuilder._version]: UserContextSignRequestBuilder,
    [CardanoTxSignRequestBuilder._name + ":" + CardanoTxSignRequestBuilder._version]: CardanoTxSignRequestBuilder,
    [RuleSettingSignRequestBuilder._name + ":" + RuleSettingSignRequestBuilder._version]: RuleSettingSignRequestBuilder

}