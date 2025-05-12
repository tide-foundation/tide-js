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

import { Point } from "../Ed25519.js";
import { RandomBigInt } from "../Math.js";
import { encryptDataRawOutput, decryptData, decryptDataRawOutput } from "./AES.js";
import { SHA256_Digest } from "../Hashing/Hash.js";
import { BigIntFromByteArray, ConcatUint8Arrays, base64ToBytes, bytesToBase64 } from "../Serialization.js";

export default class ElGamal {
    /**
     * 
     * @param {Uint8Array} secretData 
     * @param {Point} publicKey 
     */
    static async encryptData(secretData, publicKey) {
        return bytesToBase64(await this.encryptDataRaw(secretData, publicKey));
    }

    /**
     * 
     * @param {Uint8Array} secretData 
     * @param {Point} publicKey 
     */
    static async encryptDataRaw(secretData, publicKey) {
        const r = RandomBigInt();
        const c1 = Point.BASE.mul(r).toRawBytes();
        const c2 = await encryptDataRawOutput(secretData, await SHA256_Digest(publicKey.mul(r).toRawBytes()));
        return ConcatUint8Arrays([c1, c2]);
    }

    /**
     * @param {string} base64_c1_c2 
     * @param {bigint | Uint8Array} k 
     */
    static async decryptData(base64_c1_c2, k) {
        const priv = typeof(k) == 'bigint'? k : BigIntFromByteArray(k);
        const b = base64ToBytes(base64_c1_c2);
        const c1 = b.slice(0, 32);
        const c2 = b.slice(32);

        const c1Point = Point.fromBytes(c1);
        const decrypted = await decryptDataRawOutput(c2, await SHA256_Digest(c1Point.mul(priv).toRawBytes()));
        return decrypted;
    }
}