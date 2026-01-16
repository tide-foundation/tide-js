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

import { Uint8ArrayToNumber, numberToUint8Array } from "../Cryptide/Serialization.js";
import {  Serialization } from "../Cryptide/index.js";

export default class SerializedField{
    static version = 1;
    /**
     * 
     * @param {Uint8Array} encData 
     * @param {number} timestamp 
     * @param {Uint8Array} encKey
     * @param {Uint8Array} signature
     */
    static create(encData, timestamp, encKey=null, signature=null){
        // version
        const versionByte = numberToUint8Array(this.version, 1); // 1 byte
        const timestampBits = numberToUint8Array(timestamp, 8); // 64 bits (8 bytes)- let's hope Tide is still around past 2038 (otherwise i could've saved 32 bits here) https://en.wikipedia.org/wiki/Year_2038_problem

        const d = Serialization.CreateTideMemory(versionByte, 4 + 1 + 4 + encData.length + 4 + timestampBits.length + (signature == null ? 4 : 4 + signature.length)  + (encKey == null ? 4 : 4 + encKey.length));
        Serialization.WriteValue(d, 1, encData);
        Serialization.WriteValue(d, 2, timestampBits);
        Serialization.WriteValue(d, 3, encKey == null ? new Uint8Array() : encKey);
        Serialization.WriteValue(d, 4, signature == null ? new Uint8Array() : signature);

        return d;
    }
    /**
     * @param {Uint8Array} serializedField 
     */
    static deserialize(serializedField){
        // Make sure version is 1
        const version = Uint8ArrayToNumber(Serialization.GetValue(serializedField, 0));
        if(version != this.version) throw Error("Serialized tide data must be version " + this.version);

        const encFieldChk = Serialization.GetValue(serializedField, 1);
        const timestamp = Serialization.GetValue(serializedField, 2); // keep as array until JS HANDLES 64 BIT NUMBERS!
        const encKey = Serialization.GetValue(serializedField, 3);
        const signature = Serialization.GetValue(serializedField, 4);

        return {
            encFieldChk: encFieldChk,
            timestamp: timestamp,
            encKey: encKey.length == 0 ? null : encKey,
            signature: signature.length == 0 ? null : signature
        }
    }
}