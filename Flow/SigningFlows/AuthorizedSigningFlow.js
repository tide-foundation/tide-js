import { CreateTideMemory, WriteValue } from "../../Cryptide/Serialization";
import { AdminAuthorization } from "../../Models/AdminAuthorization";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import NetworkClient from "../../Clients/NetworkClient.js";
import dVVKSigningFlow from "../SigningFlows/dVVKSigningFlow.js";
import { GenSessKey, GetPublic } from "../../Cryptide/Math.js";
import { Serialization } from "../../Cryptide/index.js";
import TideKey from "../../Cryptide/TideKey.js";
import Ed25519Scheme from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js";
import { Ed25519PrivateComponent } from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import KeyInfo from "../../Models/Infos/KeyInfo.js";

/**
 * 
 * @param {{
* vendorId: string,
* token: Doken,
* sessionKey: TideKey
* voucherURL: string,
* homeOrkUrl: string | null
* keyInfo: KeyInfo
* }} config 
*/
export function AuthorizedSigningFlow(config) {
    if (!(this instanceof AuthorizedSigningFlow)) {
        throw new Error("The 'AuthorizedSigningFlow' constructor must be invoked with 'new'.")
    }

    if(!config.token.payload.sessionKey.Equals(config.sessionKey.get_public_component())) throw Error("Mismatch between session key private and Doken session key public");

    var signingFlow = this;
    signingFlow.vvkId = config.vendorId;
    signingFlow.token = config.token;
    signingFlow.voucherURL = config.voucherURL;

    signingFlow.sessKey = config.sessionKey;

    signingFlow.vvkInfo = config.keyInfo;

    /**
     * @param {Uint8Array} tideSerializedRequest 
     */
    signingFlow.signv2 = async function(tideSerializedRequest){
        const flow = new dVVKSigningFlow(this.vvkId, signingFlow.vvkInfo.UserPublic, signingFlow.vvkInfo.OrkInfo, signingFlow.sessKey, signingFlow.token, this.voucherURL);
        return flow.start(tideSerializedRequest);
    }

    signingFlow.sign = async function (dataToSign, authorizationPacks, expiry, ruleSettings) {
        signingFlow.sessKey = GenSessKey();
        signingFlow.gSessKey = GetPublic(signingFlow.sessKey);
        await getVVKInfo();
        const authPacks = authorizationPacks.map(auth => {
            return AdminAuthorization.fromString(auth)
        })

        // authorizer
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

        const data = Serialization.base64ToBytes(dataToSign);
        const draft = CreateTideMemory(data, 4 + data.length);

        const cardanoTxSignReq = new BaseTideRequest("CardanoTx", "1", "BlindSig:1", draft);
        cardanoTxSignReq.setCustomExpiry(expiry);

        cardanoTxSignReq.addAuthorizer(Authorizer);
        cardanoTxSignReq.addAuthorizerCertificate(AuthorizerSignatures);
        cardanoTxSignReq.addAuthorization(AuthorizerApprovals);
        cardanoTxSignReq.addRules(Serialization.StringToUint8Array(JSON.stringify(ruleSettings.rules)))
        cardanoTxSignReq.addRulesCert(Serialization.base64ToBytes(ruleSettings.rulesCert))


        const cardanoTxSigningFlow = new dVVKSigningFlow(this.vvkId, signingFlow.vvkInfo.UserPublic, signingFlow.vvkInfo.OrkInfo, signingFlow.sessKey, signingFlow.gSessKey, this.voucherURL);
        const signatures = await cardanoTxSigningFlow.start(cardanoTxSignReq);

        return signatures[0];
    }



}