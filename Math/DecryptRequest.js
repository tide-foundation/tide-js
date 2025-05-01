import SerializedField from "../Models/SerializedField.js";
import { encryptData, decryptData, decryptDataRawOutput } from "../Cryptide/Encryption/AES.js";
import { SHA256_Digest } from "../Cryptide/Hashing/Hash.js";
import { bytesToBase64 } from "../Cryptide/Serialization.js";
import { Point } from "../Cryptide/Ed25519.js";

export default class DecryptRequest{
    /**
     * 
     * @param {Uint8Array[]} serializedFields 
     * @param {Uint8Array[]} ECDHi 
     */
    static async generateRequests(serializedFields, ECDHi){
        const deserializedFields = serializedFields.map(field => SerializedField.deserialize(field));
        const pre_encFieldChks = deserializedFields.map(df => SHA256_Digest(df.data));
        const encFieldChks = await Promise.all(pre_encFieldChks);

        const toEncrypt = {
            Timestamps: deserializedFields.map(df => df.timestamp), // using first as theyre all the same
            EncFieldChks: encFieldChks.map(e => bytesToBase64(e)),
            C1s: deserializedFields.map(df => df.key.toBase64()),
            Tags: deserializedFields.map(df => df.tag),
            Sigs: deserializedFields.map(df => bytesToBase64(df.sig))
        }

        const pre_encRequests = ECDHi.map(ECDH => encryptData(JSON.stringify(toEncrypt), ECDH));
        const encRequests = await Promise.all(pre_encRequests);
        return {
            encRequests,
            encryptedFields: deserializedFields.map(df => df.data),
            tags: toEncrypt.Tags // i don't want to use map again here
        }
    }
    /**
     * @param {Uint8Array[]} encryptedFields
     * @param {Uint8Array[]} ECDHi 
     * @param {string[]} encryptedFieldKeys 
     * @param {bignt[]} lis 
     */
    static async decryptFields(encryptedFields, ECDHi, encryptedFieldKeys, lis){
        const pre_decryptedData = encryptedFieldKeys.map(async (encK, i) => JSON.parse(await decryptData(encK, ECDHi[i])));
        const decryptedData = await Promise.all(pre_decryptedData);

        const fieldKeys = encryptedFields.map((_, i) => decryptedData.reduce((sum, next, j) => sum.add(Point.fromBase64(next.AppliedFieldKeys[i]).mul(lis[j])), Point.ZERO)); // main loop over amount of encrypted datas

        const pre_decryptedFields = fieldKeys.map(async (fk, i) => decryptDataRawOutput(encryptedFields[i], await SHA256_Digest(fk.toRawBytes())));
        const decryptedFields = await Promise.all(pre_decryptedFields);
        return decryptedFields;
    }
}