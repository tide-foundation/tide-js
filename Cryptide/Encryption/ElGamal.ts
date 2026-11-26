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

import { Point } from "../Ed25519";
import { RandomBigInt } from "../Math";
import { encryptDataRawOutput, decryptData, decryptDataRawOutput } from "./AES";
import { SHA256_Digest } from "../Hashing/Hash";
import { BigIntFromByteArray, ConcatUint8Arrays, base64ToBytes, bytesToBase64 } from "../Serialization";
import TideKey from "../TideKey";
import { Ed25519PrivateComponent } from "../Components/Schemes/Ed25519";

export default class ElGamal {
    static async encryptData(secretData: Uint8Array, publicKey: Point) {
        return bytesToBase64(await this.encryptDataRaw(secretData, publicKey));
    }

    static async encryptDataRaw(secretData: Uint8Array, publicKey: Point) {
        const r = RandomBigInt();
        const c1 = Point.BASE.mul(r).toRawBytes();
        const c2 = await encryptDataRawOutput(secretData, await SHA256_Digest(publicKey.mul(r).toRawBytes()));
        return ConcatUint8Arrays([c1, c2]);
    }

    static async encryptDataRaw_withAuthentication(secretData: Uint8Array, publicKey: Point, authMsg: Uint8Array) {
        const r = RandomBigInt();
        const c1 = Point.BASE.mul(r).toRawBytes();
        const c2 = await encryptDataRawOutput(secretData, await SHA256_Digest(publicKey.mul(r).toRawBytes()));
        const authSig = await (new TideKey(new Ed25519PrivateComponent(r)).sign(authMsg));
        return {
            cipher: ConcatUint8Arrays([c1, c2]),
            auth: authSig
        }
    }

    static async decryptData(base64_c1_c2: string, k: bigint | Uint8Array) {
        const priv = typeof(k) == 'bigint'? k : BigIntFromByteArray(k);
        const b = base64ToBytes(base64_c1_c2);
        const c1 = b.slice(0, 32);
        const c2 = b.slice(32);

        const c1Point = Point.fromBytes(c1);
        const decrypted = await decryptDataRawOutput(c2, await SHA256_Digest(c1Point.mul(priv).toRawBytes()));
        return decrypted;
    }

    static async decryptDataRaw(base64_c1_c2: Uint8Array, k: bigint | Uint8Array) {
        const priv = typeof(k) == 'bigint'? k : BigIntFromByteArray(k);
        const c1 = base64_c1_c2.slice(0, 32);
        const c2 = base64_c1_c2.slice(32);

        const c1Point = Point.fromBytes(c1);
        const decrypted = await decryptDataRawOutput(c2, await SHA256_Digest(c1Point.mul(priv).toRawBytes()));
        return decrypted;
    }
}