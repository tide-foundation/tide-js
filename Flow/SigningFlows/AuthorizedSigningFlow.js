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
        return flow.start(BaseTideRequest.decode(tideSerializedRequest));
    }
}