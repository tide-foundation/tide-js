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

import SerializedField from "../Models/SerializedField";
import { encryptData, decryptData, decryptDataRawOutput } from "../Cryptide/Encryption/AES";
import { SHA256_Digest } from "../Cryptide/Hashing/Hash";
import { bytesToBase64 } from "../Cryptide/Serialization";
import { Point } from "../Cryptide/Ed25519";

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