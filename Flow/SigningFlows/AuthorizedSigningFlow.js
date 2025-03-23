import { CreateTideMemory, WriteValue } from "../../Cryptide/Serialization";
import { AdminAuthorization } from "../../Models/AdminAuthorization";
import { numberToUint8Array } from "../../Cryptide/Serialization.js";
import { CurrentTime } from "../../Tools/Utils.js";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import NetworkClient from "../../Clients/NetworkClient.js";
import dVVKSigningFlow from "../SigningFlows/dVVKSigningFlow.js";
import { GenSessKey, GetPublic } from "../../Cryptide/Math.js";
import { Serialization } from "../../Cryptide/index.js";

/**
 * 
 * @param {{
* vendorId: string,
* token: string,
* voucherURL: string,
* homeOrkUrl: string | null
* }} config 
*/
export function AuthorizedSigningFlow(config) {
    if (!(this instanceof AuthorizedSigningFlow)) {
        throw new Error("The 'AuthorizedSigningFlow' constructor must be invoked with 'new'.")
    }

    var signingFlow = this;
    signingFlow.vvkId = config.vendorId;
    signingFlow.token = config.token;
    signingFlow.voucherURL = config.voucherURL;

    signingFlow.sessKey = GenSessKey();
    signingFlow.gSessKey = GetPublic(signingFlow.sessKey);

    signingFlow.vvkInfo = null;
    async function getVVKInfo() {
        if (!signingFlow.vvkInfo) {
            signingFlow.vvkInfo = await new NetworkClient(config.homeOrkUrl).GetKeyInfo(signingFlow.vvkId);
        }
    }

    signingFlow.sign = async function (dataToSign, authorizationPack, expiry, ruleSettings) {
        await getVVKInfo();
        console.log(ruleSettings)

        const authPack = AdminAuthorization.fromString(authorizationPack);

        // authorizer
        const emptyUint8Array = new Uint8Array(0);

        const encodedContext = authPack.encodeContext()
        const authorizerSize = 4 + 4 + emptyUint8Array.length + encodedContext.length
        const Authorizer = CreateTideMemory(emptyUint8Array, authorizerSize);
        WriteValue(Authorizer, 1, encodedContext);

        // data to authenticate authorizer
        const authorizerSigSize = 4 + 4 + emptyUint8Array.length + authPack.getAdminCert().length

        const AuthorizerSignatures = CreateTideMemory(emptyUint8Array, authorizerSigSize)
        WriteValue(AuthorizerSignatures, 1, authPack.getAdminCert())

        // data to verify the approval
        const AuthorizerApprovals = CreateTideMemory(authPack.encodeApproval(), 4 + authPack.encodeApproval().length)


        const data = Serialization.base64ToBytes(dataToSign);
        console.log(dataToSign)
        // Start signing flow to authorize this cardano transaction
        const size = 4 + 4 + emptyUint8Array.length + data.length

        const draft = CreateTideMemory(emptyUint8Array, size);
        WriteValue(draft, 1, data)

        const cardanoTxSignReq = new BaseTideRequest("CardanoTx", "1", "BlindSig:1", draft);
        cardanoTxSignReq.setCustomExpiry(expiry);

        // Deserialize token to retrieve vuid - if it exists
        // const vuid = JSON.parse(StringFromUint8Array(base64ToBytes(base64UrlToBase64(this.token.split(".")[1])))).vuid; // get vuid field from jwt payload in 1 line
        // if (vuid) cardanoTxSignReq.dyanmicData = StringToUint8Array(vuid);

        // Set the Authorization token as the authorizer for the request
        console.log(JSON.stringify(ruleSettings.rules));
        cardanoTxSignReq.addAuthorizer(Authorizer);
        cardanoTxSignReq.addAuthorizerCertificate(AuthorizerSignatures);// special case where other field isn't required
        cardanoTxSignReq.addAuthorization(AuthorizerApprovals); // special case where other field isn't required
        cardanoTxSignReq.addRules(Serialization.StringToUint8Array(JSON.stringify(ruleSettings.rules)))
        cardanoTxSignReq.addRulesCert(Serialization.base64ToBytes(ruleSettings.rulesCert))

        // Initiate signing flow
        const cardanoTxSigningFlow = new dVVKSigningFlow(this.vvkId, signingFlow.vvkInfo.UserPublic, signingFlow.vvkInfo.OrkInfo, signingFlow.sessKey, signingFlow.gSessKey, this.voucherURL);
        const signatures = await cardanoTxSigningFlow.start(cardanoTxSignReq);

        return signatures[0];
    }



}