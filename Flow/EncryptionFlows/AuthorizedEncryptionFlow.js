import { ElGamal, Serialization } from "../../Cryptide/index.js";
import { Ed25519PublicComponent } from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import { encryptData, encryptDataRawOutput } from "../../Cryptide/Encryption/AES.js";
import { base64ToBytes, base64UrlToBase64, numberToUint8Array, StringFromUint8Array, StringToUint8Array } from "../../Cryptide/Serialization.js";
import { CurrentTime } from "../../Tools/Utils.js";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import NetworkClient from "../../Clients/NetworkClient.js";
import dVVKSigningFlow from "../SigningFlows/dVVKSigningFlow.js";
import { GenSessKey, GetPublic } from "../../Cryptide/Math.js";
import SerializedField from "../../Models/SerializedField.js";
/**
 * 
 * @param {{
 * dataToEncrypt: [
* {
*      data: string,
*      tags: string[]
* }
* ]
 * vendorId: string,
 * token: string,
 * voucherURL: string
 * }} config 
 */
export function AuthorizedEncryptionFlow(config){
    if (!(this instanceof AuthorizedEncryptionFlow)) {
        throw new Error("The 'AuthorizedEncryptionFlow' constructor must be invoked with 'new'.")
    }

    var encryptionFlow = this;

    encryptionFlow.dataToEncrypt = config.dataToEncrypt;
    encryptionFlow.vvkId = config.vendorId;
    encryptionFlow.token = config.token;
    encryptionFlow.voucherURL = config.voucherURL;

    encryptionFlow.encrypt = async function(){
        const vvkInfo = await new NetworkClient().GetKeyInfo(this.vvkId); // NO do this somewhere elsesudo docker comp

        const encReqs = await Promise.all(encryptionFlow.dataToEncrypt.map(async d => {
            const d_b = StringToUint8Array(d.data);
            if(d_b.length < 32){
                // if data is less than 32B
                // Gr. EncryptedData 
                const encryptedData = await ElGamal.encryptDataRaw(d_b, vvkInfo.UserPublic);

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
                const encryptedKey = await ElGamal.encryptDataRaw(largeDataKey, vvkInfo.UserPublic);

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

        const encryptionRequest = new BaseTideRequest("TideEncryption", "1", "AccessToken:1", draft);

        // Deserialize token to retrieve vuid - if it exists
        try{
            const vuid = JSON.parse(StringFromUint8Array(base64ToBytes(base64UrlToBase64(this.token.split(".")[1])))).vuid; // get vuid field from jwt payload in 1 line
            encryptionRequest.dyanmicData = StringToUint8Array(vuid);
        }catch{}
        
        // Set the Authorization token as the authorizer for the request
        encryptionRequest.addAuthorizer(StringToUint8Array(this.token));
        encryptionRequest.addAuthorizerCertificate(new Uint8Array());// special case where other field isn't required
        encryptionRequest.addAuthorization(new Uint8Array()); // special case where other field isn't required
        
        // Initiate signing flow
        const sessKey = GenSessKey();
        const gSessKey = GetPublic(sessKey);
        const encryptingSigningFlow = new dVVKSigningFlow(this.vvkId, vvkInfo.UserPublic, vvkInfo.OrkInfo, sessKey, gSessKey, this.voucherURL);
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
}