import dDecryptionFlow from "../Flow/dDecryptionFlow.js";
import { TideJWT } from "../index.js";
import NetworkClient from "../Clients/NetworkClient.js";
export default class Decrypt{
    /**
     * @param {string} jwt 
     * @param {Uint8Array[]} serializedFields 
     * @param {string} sessKey 
     */
    constructor(jwt, serializedFields, sessKey){
        this.jwt = jwt;
        this.serializedFields = serializedFields;
        this.sessKey = sessKey;
    }

    async start(){
        // get ork publics for the jwt's vuid
        const vuid = TideJWT.getUID(this.jwt);
        const simClient = new NetworkClient();
        const keyInfo = await simClient.GetKeyInfo(vuid);

        const decryptionFlow = new dDecryptionFlow(vuid, keyInfo);
        const datums = await decryptionFlow.Decrypt(this.jwt, this.serializedFields, this.sessKey);

        const response = {
            ok: true,
            dataType: "decrypt",
            errorEncountered: false,
            decryptedFields: datums
        };

        return response;
    }
}