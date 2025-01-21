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

import { BigIntToByteArray, ConcatUint8Arrays, Uint8ArrayToNumber, numberToUint8Array } from "../../Cryptide/Serialization.js";
import { Point } from "../../Cryptide/index.js";

export default class SerializedField{
    static version = 1;
    /**
     * 
     * @param {Uint8Array} encField 
     * @param {Point} C1 
     * @param {number} tag 
     * @param {number} timestamp 
     * @param {Point} gCVKR 
     * @param {bigint} CVKS 
     */
    static create(encField, C1, tag, timestamp, gCVKR, CVKS){
        // version
        if(this.version > 127) throw Error("Wow, Tide made it this far. Time to implement the version bit extension sucker.")
        const versionByte = numberToUint8Array(this.version, 1); // 1 byte
        const key = C1.toArray(); // 32 bytes
        const tagBytes = numberToUint8Array(tag, 8); // 8 bytes - allowing a ridiculous amount of identifiers.
        if(tagBytes.length > 8) throw Error("Tag length too long");
        const sign = ConcatUint8Arrays([gCVKR.toArray(), BigIntToByteArray(CVKS)]); // 64 bytes
        const timestampBits = numberToUint8Array(timestamp, 8); // 64 bits (8 bytes)- let's hope Tide is still around past 2038 (otherwise i could've saved 32 bits here) https://en.wikipedia.org/wiki/Year_2038_problem
        const data = encField;

        const serializedField = ConcatUint8Arrays([
            versionByte,
            key,
            tagBytes,
            sign,
            timestampBits,
            data
        ]);
        return serializedField;
    }
    /**
     * @param {Uint8Array} serializedField 
     */
    static deserialize(serializedField){
        let pos = 0;
        const version = serializedField[pos];
        pos++;
        // check version
        if(version != this.version) throw Error("Unsupported version");
        const key = Point.from(serializedField.slice(pos, pos + 32));
        pos += 32;
        const tag = Uint8ArrayToNumber(serializedField.slice(pos, pos + 8));
        pos += 8;
        const sig = serializedField.slice(pos, pos + 64);
        pos += 64;
        const timestamp = Uint8ArrayToNumber(serializedField.slice(pos, pos + 8));
        pos += 8;
        const data = serializedField.slice(pos);
        const d = {
            data,
            key,
            tag,
            timestamp,
            sig
        }
        return d;
    }
}