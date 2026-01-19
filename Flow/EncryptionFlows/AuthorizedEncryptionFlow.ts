// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

import { Encryption, Serialization } from "../../Cryptide/index";
import { decryptDataRawOutput, encryptDataRawOutput } from "../../Cryptide/Encryption/AES";
import { numberToUint8Array, StringToUint8Array } from "../../Cryptide/Serialization";
import { CurrentTime } from "../../Tools/Utils";
import BaseTideRequest from "../../Models/BaseTideRequest";
import dVVKSigningFlow from "../SigningFlows/dVVKSigningFlow";
import SerializedField from "../../Models/SerializedField";
import dVVKDecryptionFlow from "../DecryptionFlows/dVVKDecryptionFlow";
import { Doken } from "../../Models/Doken";
import TideKey from "../../Cryptide/TideKey";
import KeyInfo from "../../Models/Infos/KeyInfo";
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
export function AuthorizedEncryptionFlow(config){
    if (!(this instanceof AuthorizedEncryptionFlow)) {
        throw new Error("The 'AuthorizedEncryptionFlow' constructor must be invoked with 'new'.")
    }

    var encryptionFlow = this;

    if(!config.token.payload.sessionKey.Equals(config.sessionKey.get_public_component())) {
        throw Error("Mismatch between session key private and Doken session key public");
    }

    encryptionFlow.vvkId = config.vendorId;
    encryptionFlow.token = config.token;
    encryptionFlow.sessKey = config.sessionKey;
    encryptionFlow.voucherURL = config.voucherURL;
    

    encryptionFlow.vvkInfo = config.keyInfo;

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
        const encReqs = await Promise.all(datasToEncrypt.map(async d => {
            const d_b = d.data;
            if(d_b.length < 32){
                // if data is less than 32B
                // Gr. EncryptedData 
                const encryptedData = await Encryption.ElGamal.encryptDataRaw(d_b, encryptionFlow.vvkInfo.UserPublic);

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
                const encryptedKey = await Encryption.ElGamal.encryptDataRaw(largeDataKey, encryptionFlow.vvkInfo.UserPublic);

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

        const encryptionRequest = new BaseTideRequest("TideSelfEncryption", "1", "Doken:1", draft, null);

        // Deserialize token to retrieve vuid - if it exists
        const vuid = this.token.payload.vuid;
        if(vuid) encryptionRequest.setNewDynamicData(StringToUint8Array(vuid));
        
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
    
            const decryptionRequest = new BaseTideRequest("SelfDecrypt", "1", "Doken:1", draft, null);
    
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