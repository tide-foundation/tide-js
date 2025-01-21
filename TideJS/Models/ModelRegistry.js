import { base64ToBytes, base64UrlToBase64, GetValue, StringFromUint8Array, TryGetValue } from "../../Cryptide/Serialization.js";
import InitializationCertificate from "./InitializationCertificate.js";

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

        // return a nice object of InitCert? and usercontexts
        return prettyObject;
    }
}
class CardanoTxSignRequestBuilder extends HumanReadableModelBuilder{ // this is an example class
    static _name = "CardanoTx";
    static _version = "1";
    constructor(data, expiry){
        throw Error("Not implemented");
        super(data, expiry);
    }
    getHumanReadableObject(){
        // deserialize draft here and return a pretty object for user
        
    }
}

const modelBuildersMap = {
    [UserContextSignRequestBuilder._name + ":" + UserContextSignRequestBuilder._version]: UserContextSignRequestBuilder,
    [CardanoTxSignRequestBuilder._name + ":" + CardanoTxSignRequestBuilder._version]: CardanoTxSignRequestBuilder
}