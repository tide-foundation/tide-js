import { SHA512_Digest } from "../Cryptide/Hashing/Hash.js";
import { Serialization } from "../Cryptide/index.js";
import { base64ToBase64Url, bytesToBase64, numberToUint8Array, StringToUint8Array } from "../Cryptide/Serialization.js";
import { CurrentTime } from "../Tools/Utils.js";

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
        this.rules = new Uint8Array();
        this.rulesCert = new Uint8Array();
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


    /**
     * @param {Uint8Array} rules 
     */
    addRules(rules) {
        this.rules = rules;
    }

    /**
     * 
     * @param {Uint8Array} rulesCert 
     */
    addRulesCert(rulesCert) {
        this.rulesCert = rulesCert
    }

    async dataToAuthorize() {
        return StringToUint8Array("<datatoauthorize-" + this.name + ":" + this.version + bytesToBase64(await SHA512_Digest(this.draft)) + this.expiry.toString() + "-datatoauthorize>");
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

        const req = Serialization.CreateTideMemory(name_b,
            44 + // 11 fields * 4 byte length
            name_b.length + version_b.length + authFlow_b.length + expiry.length +
            this.draft.length + this.dyanmicData.length + this.authorizer.length + this.authorization.length + this.authorizerCert.length + this.rules.length + this.rulesCert.length
        );
        Serialization.WriteValue(req, 1, version_b);
        Serialization.WriteValue(req, 2, expiry);
        Serialization.WriteValue(req, 3, this.draft);
        Serialization.WriteValue(req, 4, authFlow_b);
        Serialization.WriteValue(req, 5, this.dyanmicData);
        Serialization.WriteValue(req, 6, this.authorizer);
        Serialization.WriteValue(req, 7, this.authorization);
        Serialization.WriteValue(req, 8, this.authorizerCert);
        Serialization.WriteValue(req, 9, this.rules);
        Serialization.WriteValue(req, 10, this.rulesCert);


        return req;
    }
}