import { SHA512_Digest } from "../Cryptide/Hashing/Hash.js";
import { Serialization } from "../Cryptide/index.js";
import { base64ToBase64Url, bytesToBase64, GetValue, numberToUint8Array, StringToUint8Array, TryGetValue } from "../Cryptide/Serialization.js";
import { PolicyAuthorizedTideRequestSignatureFormat } from "../Cryptide/Signing/TideSignature.js";

import { CurrentTime } from "../Tools/Utils.js";
import { Doken } from "./Doken.js";

export default class BaseTideRequest {
    /**
     * 
     * @param {string} name 
     * @param {string} version
     * @param {string} authFlow 
     * @param {Uint8Array} draft 
     * @param {Uint8Array} dyanmicData 
     */
    constructor(name, version, authFlow, draft, dyanmicData = new Uint8Array()) {
        this.name = name;
        this.version = version;
        this.authFlow = authFlow
        this.draft = draft.slice();
        this.dyanmicData = dyanmicData.slice();
        this.authorization = new Uint8Array();
        this.authorizerCert = new Uint8Array();;
        this.authorizer = new Uint8Array();;
        this.expiry = BigInt(CurrentTime() + 30); // default is 30s
        this.policy = new Uint8Array();
    }

    id() {
        return this.name + ":" + this.version;
    }

    /**
     * This isn't copying. Just created another BaseTideRequest object that allows you to point each individual field to OTHER sections of memory.
     * If you modify an existing 'replicated' field, you'll also modify the other object you originally replicated.
     */
    replicate(){
        const r = new BaseTideRequest(this.name, this.version, this.authFlow, this.draft, this.dyanmicData);
        r.authorization = this.authorization;
        r.authorizerCert = this.authorizerCert;
        r.authorizer = this.authorizer;
        r.expiry = this.expiry;
        r.policy = this.policy;
        return r;
    }

    /**
     * @param {Uint8Array} d 
     */
    setNewDynamicData(d){
        this.dyanmicData = d;
        return this;
    }

    /**
     * 
     * @param {number} timeFromNowInSeconds 
     */
    setCustomExpiry(timeFromNowInSeconds) {
        this.expiry = timeFromNowInSeconds;
        return this;
    }

    /**
     * @param {Uint8Array} authorizer 
     */
    addAuthorizer(authorizer) {
        this.authorizer = authorizer;
    }

    /**
     * 
     * @param {Uint8Array} authorizerCertificate 
     */
    addAuthorizerCertificate(authorizerCertificate) {
        this.authorizerCert = authorizerCertificate
    }

    /**
     * 
     * @param {Uint8Array} authorization 
     */
    addAuthorization(authorization) {
        this.authorization = authorization
        return this;
    }


    async dataToAuthorize() {
        return StringToUint8Array("<datatoauthorize-" + this.name + ":" + this.version + bytesToBase64(await SHA512_Digest(this.draft)) + this.expiry.toString() + "-datatoauthorize>");
    }

    /**
     * Add an approval for this request. To be used for policy auth flow
     * @param {Doken} doken 
     * @param {Uint8Array} sig 
     */
    addApproval(doken, sig){
        // Ensure creation authorization has been added
        let res = {};
        if(!TryGetValue(this.authorization, 0, res)) throw Error("Creation authorization hasn't been added yet");

        // Deconstruct existing authorization
        let existingSessKeySigs = [];
        let currentSig = {};
        for(let i = 0; TryGetValue(GetValue(this.authorization, 1), i, currentSig); i++){
            if(currentSig.result.length == 0) continue;
            existingSessKeySigs.push(currentSig.result);
        }

        // Now deconstruct exsiting authorizers (dokens)
        let existingDokens = [];
        let currentDoken = {};
        for(let i = 0; TryGetValue(this.authorizer, i, currentDoken); i++){
            if(currentDoken.result.length == 0) continue;
            existingDokens.push(currentDoken.result);
        }

        // Now add the new doken and sig to the deconstructed data then reserialize it into the request
        existingDokens.push(StringToUint8Array(doken.serialize()));
        existingSessKeySigs.push(sig);

        this.authorization = Serialization.CreateTideMemoryFromArray([
            GetValue(this.authorization, 0),
            Serialization.CreateTideMemoryFromArray(existingSessKeySigs)
        ]);
        this.authorizer = Serialization.CreateTideMemoryFromArray(existingDokens);
    }

    encode() {
        if (this.authorizer == null) throw Error("Authorizer not added to request");
        if (this.authorizerCert == null) throw Error("Authorizer cert not provided");
        if (this.authorization == null) throw Error("Authorize this request first with an authorizer");

        const name_b = StringToUint8Array(this.name);
        const version_b = StringToUint8Array(this.version);
        const authFlow_b = StringToUint8Array(this.authFlow);
        const expiry = new Uint8Array(8);
        const expiry_view = new DataView(expiry.buffer);
        expiry_view.setBigInt64(0, this.expiry, true);

        const req = Serialization.CreateTideMemoryFromArray([
            name_b,
            version_b,
            expiry,
            this.draft,
            authFlow_b,
            this.dyanmicData,
            this.authorizer,
            this.authorization,
            this.authorizerCert,
            this.policy
        ]);

        return req;
    }

    static decode(data){
        // Read field 0 (name) - this is part of the TideMemory structure
        const name_b = Serialization.GetValue(data, 0);
        const name = new TextDecoder().decode(name_b);
        
        // Read all other fields
        const version_b = Serialization.GetValue(data, 1);
        const version = new TextDecoder().decode(version_b);
        
        const expiry_b = Serialization.GetValue(data, 2);
        const expiry_view = new DataView(expiry_b.buffer, expiry_b.byteOffset, expiry_b.byteLength);
        const expiry = expiry_view.getBigInt64(0, true);
        
        const draft = Serialization.GetValue(data, 3);
        
        const authFlow_b = Serialization.GetValue(data, 4);
        const authFlow = new TextDecoder().decode(authFlow_b);
        
        const dynamicData = Serialization.GetValue(data, 5);
        
        const authorizer = Serialization.GetValue(data, 6);
        const authorization = Serialization.GetValue(data, 7);
        const authorizerCert = Serialization.GetValue(data, 8);
        const policy = Serialization.GetValue(data, 9);
        
        // Create a new BaseTideRequest with the decoded data
        const request = new BaseTideRequest(name, version, authFlow, draft, dynamicData);
        
        // Set the remaining fields
        request.expiry = expiry;
        request.authorizer = authorizer;
        request.authorization = authorization;
        request.authorizerCert = authorizerCert;
        request.policy = policy;
        
        return request;
    }

    async dataToApprove(){
        const creationTime =  Serialization.GetValue(Serialization.GetValue(this.authorization, 0), 0);
        const creationSig =  Serialization.GetValue(Serialization.GetValue(this.authorization, 0), 1);
        const creationMessage = new PolicyAuthorizedTideRequestSignatureFormat(creationTime, this.expiry, this.id(), await SHA512_Digest(this.draft));
        return creationMessage.format();
    }
}