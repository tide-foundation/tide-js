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

import { RandomBigInt, mod, mod_inv } from "../Math.js";
import { Point } from "../Ed25519.js";
import { SHA512_Digest } from "../Hashing/Hash.js";
import { BigIntFromByteArray, BigIntToByteArray, ConcatUint8Arrays, bytesToBase64 } from "../Serialization.js";
import { EdDSA } from "../index.js";
/**
 * 
 * @param {Point} gR 
 * @param {Point} pub 
 * @param {Uint8Array} message 
 * @param {bigint} multiplier 
 */
export async function genBlindMessage(gR, pub, message, multiplier){
    const blur = RandomBigInt();
    const gRMul = gR.mul(mod_inv(blur));
    const eddsaH = mod(BigIntFromByteArray(await SHA512_Digest(ConcatUint8Arrays([gRMul.toRawBytes(), pub.toRawBytes(), message]))));
    const blurHCMKMul = mod(eddsaH * multiplier * blur);

    return {blurHCMKMul, blur, gRMul};
}
/**
 * 
 * @param {bigint} blindS 
 * @param {bigint} blur 
 */
export async function unblindSignature(blindS, blur){
    const s = mod(blindS * mod_inv(blur));
    return s;
}

/**
 * 
 * @param {bigint} S 
 * @param {Point} noncePublic 
 * @param {Point} pub
 * @param {Uint8Array} message 
 */
export async function verifyBlindSignature(S, noncePublic, pub, message){
    const valid = await EdDSA.verifyRaw(S, noncePublic, pub, message);
    
    if(!valid){
        console.error(`Signature failed. \nM: ${bytesToBase64(message)}\nS: ${S.toString()}\nNoncePublic: ${noncePublic.toBase64()}\nPublic: ${pub.toBase64()}`);
    }
    return valid;
}

/**
 * @param {bigint} S 
 * @param {Point} noncePublic 
 */
export function serializeBlindSig(S, noncePublic){
    return ConcatUint8Arrays([BigIntToByteArray(S), noncePublic.toRawBytes()]);
}