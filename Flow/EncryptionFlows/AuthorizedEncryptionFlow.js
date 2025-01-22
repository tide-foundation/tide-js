import { BaseComponent } from "../Cryptide/Components/BaseComponent";
import { Ed25519PrivateComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components";
import { StringToUint8Array } from "../Cryptide/Serialization";
import TideKey from "../Cryptide/TideKey";

export default class AuthorizedEncryptionFlow{
    /**
     * 
     * @param {[
     * {
     *      data: string,
     *      tags: string[]
     * }
     * ]} dataToEncrypt 
     * @param {*} vendorKey 
     * @param {*} authorizationToken 
     * @param {*} voucherURL 
     */
    constructor(dataToEncrypt, vendorKey, authorizationToken, voucherURL){
        this.dataToEncrypt = dataToEncrypt;
        this.vendorKey = vendorKey;
        this.authorizationToken = authorizationToken;
        this.voucherURL = voucherURL;
    }

    async encrypt(){
        this.dataToEncrypt.forEach(d => {
            const d_b = StringToUint8Array(d.data);
            if(d_b.length < 32){
                // if data is less than 32B
                // Gr. EncryptedData 
                
            }else{

            }
            // If data to encrypt is larger than 32 bytes, create key to encrypt, store the key use

            // if data is less than 32B
            // Gr. EncryptedData 

            // if data is more than 32B
            // Gr. EncryptedKey. EncryptedData

            // Start signing flow to authorize this encryption
        })
        
    }
}