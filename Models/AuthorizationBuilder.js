import { AdminAuthorization } from "./AdminAuthorization.js";
import BaseTideRequest from "./BaseTideRequest.js";
import { WriteValue, StringToUint8Array, CreateTideMemory, base64ToBytes } from "../Cryptide/Serialization.js";


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
        const Authorizer = CreateTideMemory(authPacks[0].encodeContext(), authorizerSize);
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

        this.tideRequest.addAuthorizer(Authorizer);
        this.tideRequest.addAuthorizerCertificate(AuthorizerSignatures);
        this.tideRequest.addAuthorization(AuthorizerApprovals);
        if(this.ruleSettings !== null) {
            this.tideRequest.addRules(StringToUint8Array(JSON.stringify(this.ruleSettings.rules)))
            this.tideRequest.addRulesCert(base64ToBytes(this.ruleSettings.rulesCert))
        }
    }
}
