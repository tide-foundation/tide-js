import { SHA256_Digest } from "../Cryptide/Hashing/Hash.js";
import { ConcatUint8Arrays, bytesToBase64, numberToUint8Array } from "../Cryptide/Serialization.js";
import { RandomBigInt, mod } from "../Cryptide/Math.js";
import { EdDSA } from "../Cryptide/index.js";
import { decryptData, encryptData, encryptDataRawOutput } from "../Cryptide/Encryption/AES.js";
import Datum from "../Models/Datum.js";
import SerializedField from "../Models/SerializedField.js";
import { Point } from "../Cryptide/Ed25519.js";

export default class EncryptRequest{
    /**
     * 
     * @param {Point} gCVK 
     * @param {Uint8Array} fieldDatum 
     * @param {number} timestamp
     */
    static async generatePartialRequest(gCVK, fieldDatum, timestamp){
        const ephKey = RandomBigInt(); // not to be stored
        const fieldKey = await SHA256_Digest((gCVK.mul(ephKey).toRawBytes())); // not to be stored
        const encField = await encryptDataRawOutput(fieldDatum, fieldKey);

        const data = {
            C1: Point.BASE.mul(ephKey),
            EncField: encField,
            EncFieldChk: await SHA256_Digest(encField),
            timestamp: timestamp
        }
        return data;
    }

    /**
     * @param {{
            C1: Point;
            EncField: Uint8Array;
            EncFieldChk: Uint8Array;
            timestamp: number;
        }[]} partialRequests 
     * @param {bigint} li 
     * @param {Datum[]} datums 
     * @param {Point[]} gCVKRi 
     * @param {Uint8Array} ECDHi 
     */
    static async generateEncryptedRequest(partialRequests, li, datums, gCVKRi, ECDHi){
        const toEncrypt = {
            Timestamp: partialRequests[0].timestamp, // using first as theyre all the same
            EncFieldChks: partialRequests.map(p => bytesToBase64(p.EncFieldChk)),
            C1s: partialRequests.map(p => p.C1.toBase64()),
            Tags: datums.map(d => d.tag),
            GCVKRi: gCVKRi.map(gcvkr => gcvkr.toBase64()),
            Li: li.toString()
        }
        const encrypted = await encryptData(JSON.stringify(toEncrypt), ECDHi);
        return encrypted;
    }

    /**
     * Will decrypt encrypted sigs, validate those sigs, and generate the serialized fields for the vendor to store
     * @param {string[]} encryptedS
     * @param  {{
            EncFields: Uint8Array[];
            EncFieldChks: Uint8Array[];
            C1s: Point[];
            Tags: number[];
            GCVKRi: Point[];
            Timestamp: number;
        }} plainRequest
     * @param {bigint[]} lis
     * @param {Uint8Array[]} ECDHi
     * @param {Point} gCVK
     */
    static async generateSerializedFields(encryptedS, plainRequest, lis, ECDHi, gCVK){
        const pre_decryptedData = encryptedS.map(async (encS, i) => JSON.parse(await decryptData(encS, ECDHi[i])));
        const decryptedData = await Promise.all(pre_decryptedData);

        const CVKSi = plainRequest.C1s.map((_, i) => mod(decryptedData.reduce((sum, next, j) => sum + mod(BigInt(next.Si[i]) * lis[j]), BigInt(0))));

        // validate signatures
        for(let i = 0; i < plainRequest.C1s.length; i++){
            const M = await SHA256_Digest(ConcatUint8Arrays([
                plainRequest.EncFieldChks[i],
                plainRequest.C1s[i].toRawBytes(),
                numberToUint8Array(plainRequest.Tags[i], 8),
                numberToUint8Array(plainRequest.Timestamp, 8)
            ]));
            const valid = await EdDSA.verifyRaw(CVKSi[i], plainRequest.GCVKRi[i], gCVK, M);
            if(valid == false){
                throw Error("Generalize Serialized Fields: Not all fields passed verification");
            }
        };
        
        // Create Serialized Fields as neat little byte arrays
        const serializedFields = CVKSi.map((CVKS, i) => SerializedField.create(
            plainRequest.EncFields[i], 
            plainRequest.C1s[i], 
            plainRequest.Tags[i], 
            plainRequest.Timestamp, 
            plainRequest.GCVKRi[i], 
            CVKS
        ));
        return serializedFields;
    }
}