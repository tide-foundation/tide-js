import { ElGamal, Serialization } from "../../Cryptide/index.js";
import { Ed25519PrivateComponent, Ed25519PublicComponent } from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import { decryptDataRawOutput, encryptData, encryptDataRawOutput } from "../../Cryptide/Encryption/AES.js";
import { base64ToBytes, base64UrlToBase64, numberToUint8Array, StringFromUint8Array, StringToUint8Array } from "../../Cryptide/Serialization.js";
import { CurrentTime } from "../../Tools/Utils.js";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import NetworkClient from "../../Clients/NetworkClient.js";
import dVVKSigningFlow from "../SigningFlows/dVVKSigningFlow.js";
import { GenSessKey, GetPublic } from "../../Cryptide/Math.js";
import SerializedField from "../../Models/SerializedField.js";
import dVVKDecryptionFlow from "../DecryptionFlows/dVVKDecryptionFlow.js";
import { Doken } from "../../Models/Doken.js";
import TideKey from "../../Cryptide/TideKey.js";
/**
 * 
 * @param {{
 * vendorId: string,
 * token: Doken,
 * sessionKey: TideKey
 * voucherURL: string,
 * homeOrkUrl: string | null
 * }} config 
 */
export function AuthorizedEncryptionFlow(config){
    if (!(this instanceof AuthorizedEncryptionFlow)) {
        throw new Error("The 'AuthorizedEncryptionFlow' constructor must be invoked with 'new'.")
    }

    var encryptionFlow = this;

    if(!config.token.payload.sessionKey.Equals(config.sessionKey.get_public_component())) throw Error("Mismatch between session key private and Doken session key public");

    encryptionFlow.vvkId = config.vendorId;
    encryptionFlow.token = config.token;
    encryptionFlow.sessKey = config.sessionKey;
    encryptionFlow.voucherURL = config.voucherURL;
    

    encryptionFlow.vvkInfo = null;
    async function getVVKInfo(){
        if(!encryptionFlow.vvkInfo){
            encryptionFlow.vvkInfo = await new NetworkClient(config.homeOrkUrl).GetKeyInfo(encryptionFlow.vvkId);
        }
    }

    /**
     * 
     * @param {[
    * {
    *      data: Uint8Array,
    *      tags: string[]
    * }
    * ]} datasToEncrypt 
     * @returns 
     */
    encryptionFlow.encrypt = async function(datasToEncrypt){
        await getVVKInfo();

        const encReqs = await Promise.all(datasToEncrypt.map(async d => {
            const d_b = d.data;
            if(d_b.length < 32){
                // if data is less than 32B
                // Gr. EncryptedData 
                const encryptedData = await ElGamal.encryptDataRaw(d_b, encryptionFlow.vvkInfo.UserPublic);

                const tags_b = d.tags.map(t => StringToUint8Array(t)); 

                return {
                    encryptionToSign: encryptedData,
                    encryptedData: encryptedData,
                    tags : tags_b,
                    sizeLessThan32 : true
                };
                
            }else{
                // if data is more than 32B
                const largeDataKey = window.crypto.getRandomValues(new Uint8Array(32));
                const encryptedData = await encryptDataRawOutput(d_b, largeDataKey);
                const encryptedKey = await ElGamal.encryptDataRaw(largeDataKey, encryptionFlow.vvkInfo.UserPublic);

                const tags_b = d.tags.map(t => StringToUint8Array(t)); 

                return {
                    encryptionToSign : encryptedKey,
                    encryptedData : encryptedData,
                    tags: tags_b,
                    sizeLessThan32 : false
                };
            }
        }));

        // Start signing flow to authorize this encryption
        const timestamp = CurrentTime();
        const timestamp_b = numberToUint8Array(timestamp, 8);
        const size = encReqs.reduce((sum, next) => {
            // init 4 + as we'll be creating tide memory within tide memory
            // + 4 again since its another index
            const nsize =  4 + 4 + (4 + next.encryptionToSign.length + next.tags.reduce((sum, next) => sum + 4 + next.length, 0));
            return sum + nsize;
        }, 0) + 4 + timestamp_b.length; 

        const draft = Serialization.CreateTideMemory(timestamp_b, size);
        encReqs.forEach((enc, i) => {
            const entry = Serialization.CreateTideMemory(enc.encryptionToSign, 4 + enc.encryptionToSign.length + enc.tags.reduce((sum, next) => sum + 4 + next.length, 0));
            enc.tags.forEach((tag, j) => {
                Serialization.WriteValue(entry, j+1, tag);
            })
            Serialization.WriteValue(draft, i+1, entry);
        })

        const encryptionRequest = new BaseTideRequest("TideSelfEncryption", "1", "Doken:1", draft);

        // Deserialize token to retrieve vuid - if it exists
        const vuid = this.token.payload.vuid;
        if(vuid) encryptionRequest.dyanmicData = StringToUint8Array(vuid);
        
        // Initiate signing flow
        const encryptingSigningFlow = new dVVKSigningFlow(this.vvkId, encryptionFlow.vvkInfo.UserPublic, encryptionFlow.vvkInfo.OrkInfo, encryptionFlow.sessKey, encryptionFlow.token, this.voucherURL);
        const signatures = await encryptingSigningFlow.start(encryptionRequest);

        // Construct final serialized payloads for client to store
        return signatures.map((sig, i) => 
            SerializedField.create(
                encReqs[i].encryptedData,
                timestamp,
                encReqs[i].sizeLessThan32 ? null : encReqs[i].encryptionToSign,
                sig)
        )
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
        encryptionFlow.decrypt = async function(datasToDecrypt){
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
    
            const decryptionRequest = new BaseTideRequest("SelfDecrypt", "1", "Doken:1", draft);
    
            await pre_info;
    
            const flow = new dVVKDecryptionFlow(this.vvkId, this.vvkInfo.UserPublic, this.vvkInfo.OrkInfo, this.sessKey, this.token, this.voucherURL);
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