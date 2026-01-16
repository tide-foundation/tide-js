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
Object.defineProperty(exports, "__esModule", { value: true });
const Serialization_1 = require("../Cryptide/Serialization");
const index_1 = require("../Cryptide/index");
class SerializedField {
    /**
     *
     * @param {Uint8Array} encData
     * @param {number} timestamp
     * @param {Uint8Array} encKey
     * @param {Uint8Array} signature
     */
    static create(encData, c1, tag, timestamp, gcvkr, encKey = null, signature = null) {
        // Handle different calling signatures
        if (arguments.length <= 4) {
            // Old signature: create(encData, timestamp, encKey, signature)
            timestamp = c1;
            encKey = tag;
            signature = timestamp;
        }
        // New signature: create(encData, c1, tag, timestamp, gcvkr, encKey)
        // Already has correct parameters
        // version
        const versionByte = (0, Serialization_1.numberToUint8Array)(this.version, 1); // 1 byte
        const timestampBits = (0, Serialization_1.numberToUint8Array)(timestamp, 8); // 64 bits (8 bytes)- let's hope Tide is still around past 2038 (otherwise i could've saved 32 bits here) https://en.wikipedia.org/wiki/Year_2038_problem
        const d = index_1.Serialization.CreateTideMemory(versionByte, 4 + 1 + 4 + encData.length + 4 + timestampBits.length + (signature == null ? 4 : 4 + signature.length) + (encKey == null ? 4 : 4 + encKey.length));
        index_1.Serialization.WriteValue(d, 1, encData);
        index_1.Serialization.WriteValue(d, 2, timestampBits);
        index_1.Serialization.WriteValue(d, 3, encKey == null ? new Uint8Array() : encKey);
        index_1.Serialization.WriteValue(d, 4, signature == null ? new Uint8Array() : signature);
        return d;
    }
    /**
     * @param {Uint8Array} serializedField
     */
    static deserialize(serializedField) {
        // Make sure version is 1
        const version = (0, Serialization_1.Uint8ArrayToNumber)(index_1.Serialization.GetValue(serializedField, 0));
        if (version != this.version)
            throw Error("Serialized tide data must be version " + this.version);
        const encFieldChk = index_1.Serialization.GetValue(serializedField, 1);
        const timestamp = index_1.Serialization.GetValue(serializedField, 2); // keep as array until JS HANDLES 64 BIT NUMBERS!
        const encKey = index_1.Serialization.GetValue(serializedField, 3);
        const signature = index_1.Serialization.GetValue(serializedField, 4);
        return {
            encFieldChk: encFieldChk,
            timestamp: timestamp,
            encKey: encKey.length == 0 ? null : encKey,
            signature: signature.length == 0 ? null : signature
        };
    }
}
SerializedField.version = 1;
exports.default = SerializedField;
