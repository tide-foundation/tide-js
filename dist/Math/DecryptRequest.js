"use strict";
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const SerializedField_1 = __importDefault(require("../Models/SerializedField"));
const AES_1 = require("../Cryptide/Encryption/AES");
const Hash_1 = require("../Cryptide/Hashing/Hash");
const Serialization_1 = require("../Cryptide/Serialization");
const Ed25519_1 = require("../Cryptide/Ed25519");
class DecryptRequest {
    /**
     *
     * @param {Uint8Array[]} serializedFields
     * @param {Uint8Array[]} ECDHi
     */
    static async generateRequests(serializedFields, ECDHi) {
        const deserializedFields = serializedFields.map(field => SerializedField_1.default.deserialize(field));
        const pre_encFieldChks = deserializedFields.map(df => (0, Hash_1.SHA256_Digest)(df.data));
        const encFieldChks = await Promise.all(pre_encFieldChks);
        const toEncrypt = {
            Timestamps: deserializedFields.map(df => df.timestamp), // using first as theyre all the same
            EncFieldChks: encFieldChks.map(e => (0, Serialization_1.bytesToBase64)(e)),
            C1s: deserializedFields.map(df => df.key.toBase64()),
            Tags: deserializedFields.map(df => df.tag),
            Sigs: deserializedFields.map(df => (0, Serialization_1.bytesToBase64)(df.sig))
        };
        const pre_encRequests = ECDHi.map(ECDH => (0, AES_1.encryptData)(JSON.stringify(toEncrypt), ECDH));
        const encRequests = await Promise.all(pre_encRequests);
        return {
            encRequests,
            encryptedFields: deserializedFields.map(df => df.data),
            tags: toEncrypt.Tags // i don't want to use map again here
        };
    }
    /**
     * @param {Uint8Array[]} encryptedFields
     * @param {Uint8Array[]} ECDHi
     * @param {string[]} encryptedFieldKeys
     * @param {bignt[]} lis
     */
    static async decryptFields(encryptedFields, ECDHi, encryptedFieldKeys, lis) {
        const pre_decryptedData = encryptedFieldKeys.map(async (encK, i) => JSON.parse(await (0, AES_1.decryptData)(encK, ECDHi[i])));
        const decryptedData = await Promise.all(pre_decryptedData);
        const fieldKeys = encryptedFields.map((_, i) => decryptedData.reduce((sum, next, j) => sum.add(Ed25519_1.Point.fromBase64(next.AppliedFieldKeys[i]).mul(lis[j])), Ed25519_1.Point.ZERO)); // main loop over amount of encrypted datas
        const pre_decryptedFields = fieldKeys.map(async (fk, i) => (0, AES_1.decryptDataRawOutput)(encryptedFields[i], await (0, Hash_1.SHA256_Digest)(fk.toRawBytes())));
        const decryptedFields = await Promise.all(pre_decryptedFields);
        return decryptedFields;
    }
}
exports.default = DecryptRequest;
