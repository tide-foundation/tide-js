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
exports.genBlindMessage = genBlindMessage;
exports.unblindSignature = unblindSignature;
exports.verifyBlindSignature = verifyBlindSignature;
exports.serializeBlindSig = serializeBlindSig;
const Math_1 = require("../Math");
const Hash_1 = require("../Hashing/Hash");
const Serialization_1 = require("../Serialization");
const index_1 = require("../index");
/**
 *
 * @param {Point} gR
 * @param {Point} pub
 * @param {Uint8Array} message
 * @param {bigint} multiplier
 */
async function genBlindMessage(gR, pub, message, multiplier) {
    const blur = (0, Math_1.RandomBigInt)();
    const gRMul = gR.mul((0, Math_1.mod_inv)(blur));
    const eddsaH = (0, Math_1.mod)((0, Serialization_1.BigIntFromByteArray)(await (0, Hash_1.SHA512_Digest)((0, Serialization_1.ConcatUint8Arrays)([gRMul.toRawBytes(), pub.toRawBytes(), message]))));
    const blurHCMKMul = (0, Math_1.mod)(eddsaH * multiplier * blur);
    return { blurHCMKMul, blur, gRMul };
}
/**
 *
 * @param {bigint} blindS
 * @param {bigint} blur
 */
async function unblindSignature(blindS, blur) {
    const s = (0, Math_1.mod)(blindS * (0, Math_1.mod_inv)(blur));
    return s;
}
/**
 *
 * @param {bigint} S
 * @param {Point} noncePublic
 * @param {Point} pub
 * @param {Uint8Array} message
 */
async function verifyBlindSignature(S, noncePublic, pub, message) {
    const valid = await index_1.EdDSA.verifyRaw(S, noncePublic, pub, message);
    if (!valid) {
        console.error(`Signature failed. \nM: ${(0, Serialization_1.bytesToBase64)(message)}\nS: ${S.toString()}\nNoncePublic: ${noncePublic.toBase64()}\nPublic: ${pub.toBase64()}`);
    }
    return valid;
}
/**
 * @param {bigint} S
 * @param {Point} noncePublic
 */
function serializeBlindSig(S, noncePublic) {
    return (0, Serialization_1.ConcatUint8Arrays)([(0, Serialization_1.BigIntToByteArray)(S), noncePublic.toRawBytes()]);
}
