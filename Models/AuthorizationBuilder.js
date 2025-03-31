import { AdminAuthorization } from "./AdminAuthorization";
import BaseTideRequest from "../Models/BaseTideRequest.js";


export default class AuthorizationBuilder {

    constructor( tideRequest = null, authorizationPacks = null, ruleSettings = null) {
        this.tideRequest = tideRequest;
        this.authorizationPacks = authorizationPacks;
        this.ruleSettings = ruleSettings;
    }

    /**
     * @param {BaseTideRequest} request 
     */
    setTideRequest(request){
        this.tideRequest = request;
    }

    /**
     * @param {Uint8Array} authPacks 
     */
    setAuthorizationPacks(authPacks){
        this.authorizationPacks = authPacks;
    }

    setRuleSettings(ruleSettings){
        this.ruleSettings = ruleSettings;
    }

    addAuthorization(){
        const authPacks = this.authorizationPacks.map(auth => {
            return AdminAuthorization.fromString(auth)
        })

        // add authorizer
        const authorizerSize = authPacks.reduce((sum, a) => sum + (a.encodeContext().length + 4), 0);
        const Authorizer = CreateTideMemory(authPacks[0], authorizerSize);
        for (let i = 1; i < authPacks.length; i++) {
            WriteValue(Authorizer, 1, authPacks[i].encodeContext());
        }

        // data to authenticate authorizer
        const authorizerSigSize = authPacks.reduce((sum, a) => sum + (a.getAdminCert().length + 4), 0)

        const AuthorizerSignatures = CreateTideMemory(authPacks[0].getAdminCert(), authorizerSigSize)

        for (let i = 1; i < authPacks.length; i++) {
            WriteValue(AuthorizerSignatures, i, authPacks[i].getAdminCert());
        }

        // data to verify the approval
        const AuthorizerApprovals = CreateTideMemory(authPacks[0].encodeApproval(), authPacks.reduce((sum, a) => sum + (a.encodeApproval().length + 4), 0))
        for (let i = 1; i < authPacks.length; i++) {
            WriteValue(AuthorizerApprovals, i, authPacks[i].encodeApproval());
        }

        tideRequest.addAuthorizer(Authorizer);
        tideRequest.addAuthorizerCertificate(AuthorizerSignatures);// special case where other field isn't required
        tideRequest.addAuthorization(AuthorizerApprovals); // special case where other field isn't required
        if(this.ruleSettings !== null) {
            tideRequest.addRules(Serialization.StringToUint8Array(JSON.stringify(ruleSettings.rules)))
            tideRequest.addRulesCert(Serialization.base64ToBytes(ruleSettings.rulesCert))
        }

        return this.tideRequest;
    }
}
