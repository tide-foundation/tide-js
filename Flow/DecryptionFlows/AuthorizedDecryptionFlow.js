import NetworkClient from "../../Clients/NetworkClient.js";
import { decryptDataRawOutput } from "../../Cryptide/Encryption/AES.js";
import { Serialization } from "../../Cryptide/index.js";
import { GenSessKey, GetPublic } from "../../Cryptide/Math.js";
import { base64ToBytes, base64UrlToBase64, StringFromUint8Array, StringToUint8Array } from "../../Cryptide/Serialization.js";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import SerializedField from "../../Models/SerializedField.js";
import dVVKDecryptionFlow from "./dVVKDecryptionFlow.js";

/**
 * 
 * @param {{
 * vendorId: string,
 * token: string,
 * voucherURL: string
 * }} config 
 */
export function AuthorizedDecryptionFlow(config){
    if (!(this instanceof AuthorizedDecryptionFlow)) {
        throw new Error("The 'AuthorizedDecryptionFlow' constructor must be invoked with 'new'.")
    }

    var decryptionFlow = this;

    decryptionFlow.vvkId = config.vendorId;
    decryptionFlow.token = config.token;
    decryptionFlow.voucherURL = config.voucherURL;

    decryptionFlow.sessKey = GenSessKey();
    decryptionFlow.gSessKey = GetPublic(decryptionFlow.sessKey);

    decryptionFlow.vvkInfo = null;
    async function getVVKInfo(){
        if(!decryptionFlow.vvkInfo){
            decryptionFlow.vvkInfo = await new NetworkClient().GetKeyInfo(decryptionFlow.vvkId);
        }
    }

    /**
     * 
     * @param {[
     * {
     *    encrypted: Uint8Array,
     *    tags: string[]
     * }
     * ]} datasToDecrypt 
     */
    decryptionFlow.decrypt = async function(datasToDecrypt){
        // Deserialize all datasToDecrypt + include tags in object
        const deserializedDatas = datasToDecrypt.map(d => {
            const b = SerializedField.deserialize(d.encrypted);
            if(b.signature == null) throw Error("Signature must be provided in Tide Serialized Data to an Authorized Decryption");
            const tags_b = d.tags.map(t => StringToUint8Array(t));
            return {
                ...b,
                tags: tags_b
            }
        })

        // Get orks to apply vvk
        const pre_info = getVVKInfo();

        const entries = deserializedDatas.map((data, i) => {
            if(data.encKey){
                // We must decrypt the encrypted key, not the data itself
                const entry = Serialization.CreateTideMemory(data.encKey, 4 + data.encKey.length + 4 + data.signature.length + 4 + data.timestamp.length + data.tags.reduce((sum, next) => sum + 4 + next.length, 0));
                Serialization.WriteValue(entry, 1, data.signature); // won't be null
                Serialization.WriteValue(entry, 2, data.timestamp);
                data.tags.forEach((tag, j) => {
                    Serialization.WriteValue(entry, j+3, tag); // + 3 as we start at index 3
                })
            return entry;
            }else{
                // decrypt data directly
                const entry = Serialization.CreateTideMemory(data.encFieldChk, 4 + data.encFieldChk.length + 4 + data.signature.length + 4 + data.timestamp.length + data.tags.reduce((sum, next) => sum + 4 + next.length, 0));
                Serialization.WriteValue(entry, 1, data.signature); // won't be null
                Serialization.WriteValue(entry, 2, data.timestamp);
                data.tags.forEach((tag, j) => {
                    Serialization.WriteValue(entry, j+3, tag); // + 3 as we start at index 3
                })
                return entry;
            }
            
        })

        const draft = Serialization.CreateTideMemory(entries[0], entries.reduce((sum, next) => sum +  4 + next.length, 0));
        for(let i = 1; i < entries.length; i++){
            Serialization.WriteValue(draft, i, entries[i]);
        }

        const decryptionRequest = new BaseTideRequest("SelfDecrypt", "1", "AccessToken:1", draft);

        // Deserialize token to retrieve vuid - if it exists
        const vuid = JSON.parse(StringFromUint8Array(base64ToBytes(base64UrlToBase64(this.token.split(".")[1])))).vuid; // get vuid field from jwt payload in 1 line
        if(vuid) decryptionRequest.dyanmicData = StringToUint8Array(vuid);
        
        // Set the Authorization token as the authorizer for the request
        decryptionRequest.addAuthorizer(StringToUint8Array(this.token));
        decryptionRequest.addAuthorizerCertificate(new Uint8Array());// special case where other field isn't required
        decryptionRequest.addAuthorization(new Uint8Array()); // special case where other field isn't required

        await pre_info;

        const flow = new dVVKDecryptionFlow(this.vvkId, this.vvkInfo.UserPublic, this.vvkInfo.OrkInfo, this.sessKey, this.gSessKey, this.voucherURL);
        const dataKeys = await flow.start(decryptionRequest);

        // Decrypt all datas
        const decryptedDatas = await Promise.all(deserializedDatas.map(async (data, i) => {
            // if encKey exists - decrypt with elgamal that
            // then decrypt encField with key
            if(data.encKey){
                const key = await decryptDataRawOutput(data.encKey.slice(32), dataKeys[i]);
                return await decryptDataRawOutput(data.encFieldChk, key);
            }else{
                // else - decrypt encField with elgamal
                return await decryptDataRawOutput(data.encFieldChk.slice(32), dataKeys[i]);
            }
        }));

        // Return as bytes
        return decryptedDatas;
    }
}