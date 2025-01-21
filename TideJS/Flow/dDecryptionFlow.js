import DecryptRequest from "../Math/DecryptRequest.js";
import NodeClient from "../Clients/NodeClient.js";
import { generateECDHi } from "../../Cryptide/Encryption/DH.js";
import KeyInfo from "../Models/Infos/KeyInfo.js";
import { WaitForNumberOfORKs } from "../Tools/Utils.js";
import Datum from "../Models/Datum.js";
import { GetLis } from "../Math/SecretShare.js";
export default class dDecryptionFlow{
    /**
     * @param {string} vuid 
     * @param {KeyInfo} keyInfo 
     */
    constructor(vuid, keyInfo){
        this.vuid = vuid
        this.keyPub = keyInfo.keyPublic
        this.CVKOrks = keyInfo.orkInfo
    }

    /**
     * 
     * @param {string} tideJWT 
     * @param {Uint8Array[]} serializedFields 
     * @param {*} sessKey 
     * @returns 
     */
    async Decrypt(tideJWT, serializedFields, sessKey){
        const clients = this.CVKOrks.map(ork => new NodeClient(ork.orkURL));
        const ECDHi = await generateECDHi(this.CVKOrks.map(ork => ork.orkPublic), sessKey); // i can either put this here, AFTER the WaitForTNumberOrks func or put it earlier, save the user 80ms, and have to manually sort and filter it here

        const {encRequests, encryptedFields, tags} = await DecryptRequest.generateRequests(serializedFields, ECDHi);

        const pre_encryptedFieldKeys = clients.map((client, i) => client.Decrypt(i, this.vuid, tideJWT, encRequests[i]));
        /**@type {string[]} */
        const encryptedFieldKeys = await WaitForNumberOfORKs(this.CVKOrks, pre_encryptedFieldKeys, "CVK", ECDHi);
        const lis = GetLis(this.CVKOrks);

        const decryptedFields = await DecryptRequest.decryptFields(encryptedFields, ECDHi, encryptedFieldKeys, lis);

        const datums = decryptedFields.map((df, i) => new Datum(df, tags[i]).toObject());
        return datums;
    }
}