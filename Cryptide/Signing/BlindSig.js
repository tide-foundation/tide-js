import { RandomBigInt, mod, mod_inv } from "../Math.js";
import Point from "../Ed25519.js";
import { SHA256_Digest, SHA512_Digest } from "../Hashing/Hash.js";
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
    const gRMul = gR.times(mod_inv(blur));
    const eddsaH = mod(BigIntFromByteArray(await SHA512_Digest(ConcatUint8Arrays([gRMul.toArray(), pub.toArray(), message]))));
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
    return ConcatUint8Arrays([BigIntToByteArray(S), noncePublic.toArray()]);
}