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
import { SHA256_Digest } from "../Hashing/Hash";
import { BigIntFromByteArray, base64ToBytes } from "../Serialization";

/**
 * @param {Point} pub 
 * @param {BigInt|string|Uint8Array} priv 
 */
export async function computeSharedKey(pub, priv){
    let privNum;
    if(typeof(priv) == "string"){
        privNum =  BigIntFromByteArray(base64ToBytes(priv))
    } else if(priv instanceof Uint8Array){
        privNum = BigIntFromByteArray(priv);
    }else if(typeof(priv) == "bigint"){
        privNum = priv;
    }else throw Error("Unknown Type");
    return await SHA256_Digest(pub.mul(privNum).toRawBytes());
}

/**
 * 
 * @param {Point[]} pubs 
 * @param {bigint|string|Uint8Array} priv 
 */
export async function generateECDHi(pubs, priv){
    const pre_ecdhi = pubs.map(async(pub) => computeSharedKey(pub, priv));
    const ecdhi = await Promise.all(pre_ecdhi);
    return ecdhi;
}