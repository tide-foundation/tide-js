import TideJWT from "../ModelsToSign/TideJWT.js"
import NetworkClient from "../Clients/NetworkClient.js";
import dEncryptionFlow from "../Flow/dEncryptionFlow.js";
import Datum from "../Models/Datum.js";
import { bytesToBase64 } from "../../Cryptide/Serialization.js";

export default class Encrypt{
    /**
     * @param {string} jwt 
     * @param {Datum[]} datums 
     * @param {string} sessionKey
     */
    constructor(jwt, datums, sessionKey){
        this.jwt = jwt
        this.datums = datums
        this.sessionKey = sessionKey
    }

    async start(){
        // get ork publics for the jwt's vuid
        const vuid = TideJWT.getUID(this.jwt);
        const simClient = new NetworkClient();
        const keyInfo = await simClient.GetKeyInfo(vuid);

        // start presign in
        const dEncryptFlow = new dEncryptionFlow(vuid, keyInfo);
        await dEncryptFlow.PreSignInEncrypt(this.jwt, this.datums, this.sessionKey);
        const serializedFields = await dEncryptFlow.SignEncryptedRequest(this.jwt);

        const response = {
            ok: true,
            dataType: "encrypt",
            errorEncountered: false,
            encryptedFields: serializedFields.map(sf => bytesToBase64(sf)) // chrome extension can't send bytearrays
        }
        return response;
    }
}