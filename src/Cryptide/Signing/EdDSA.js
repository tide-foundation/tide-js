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

import Point from "../Ed25519.js";
import { SHA512_Digest } from "../Hashing/Hash.js";
import { RandomBigInt, mod } from "../Math.js";
import { base64ToBytes, BigIntFromByteArray, BigIntToByteArray, bytesToBase64, ConcatUint8Arrays, StringToUint8Array } from "../Serialization.js";


/**
 * Sign the msg with a private key in non-standard way as it uses a random number generator. Non-deterministic.
 * @param {string | Uint8Array} msg 
 * @param {bigint} priv // Most likely the CVK
 * @returns A base64 encoding of the signature
 */
export async function sign(msg, priv){
    if(typeof(msg) == 'string'){
        msg = StringToUint8Array(msg);
    }

    const A = Point.g.times(priv).toArray();
    const r = RandomBigInt();
    const R = Point.g.times(r).toArray();

    const to_hash2 = ConcatUint8Arrays([R, A, msg]);
    const k = mod(BigIntFromByteArray(await SHA512_Digest(to_hash2)));
    const S = mod(r + (k * priv));

    const sig_bytes = ConcatUint8Arrays([R, BigIntToByteArray(S)]);
    return bytesToBase64(sig_bytes);
}

/**
 * Verify a EdDSA signature, given a signature, public key and message.
 * @param {string} sig In base64
 * @param {string | Point} pub 
 * @param {string | Uint8Array} msg 
 * @returns Boolean dependant on whether the signature is valid or not.
 */
export async function verify(sig, pub, msg){
    try{
        if(typeof(msg) == 'string'){
            msg = StringToUint8Array(msg);
        }
    
        const sig_bytes = base64ToBytes(sig);
        if(sig_bytes.length != 64) return false;
    
        const R = Point.from(sig_bytes.slice(0, 32));
        const S = BigIntFromByteArray(sig_bytes.slice(-32));
        const A = typeof(pub) === 'string' ? Point.fromB64(pub) : pub;
        
        return await verifyRaw(S, R, A, msg)
    }catch{
        return false // very strict indeed
    }
}

/**
 * Verify a message with raw S and R
 * @param {bigint} S 
 * @param {Point} R 
 * @param {Point} A 
 * @param {Uint8Array} M 
 */
export async function verifyRaw(S, R, A, M){
    if(S < BigInt(0) || S >= Point.order){
        return false;
    } 

    const to_hash = ConcatUint8Arrays([R.toArray(), A.toArray(), M]);
    const k = mod(BigIntFromByteArray(await SHA512_Digest(to_hash)));
    return Point.g.times(S).times(BigInt(8)).isEqual(R.times(BigInt(8)).add(A.times(k).times(BigInt(8))));
}