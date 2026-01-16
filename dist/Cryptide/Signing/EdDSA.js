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
exports.sign = sign;
exports.verify = verify;
exports.verifyRaw = verifyRaw;
const Ed25519_1 = require("../Ed25519");
const Hash_1 = require("../Hashing/Hash");
const Math_1 = require("../Math");
const Serialization_1 = require("../Serialization");
/**
 * Sign the msg with a private key in non-standard way as it uses a random number generator. Non-deterministic.
 * @param {string | Uint8Array} msg
 * @param {bigint} priv
 * @returns A base64 encoding of the signature
 */
async function sign(msg, priv) {
    if (typeof (msg) == 'string') {
        msg = (0, Serialization_1.StringToUint8Array)(msg);
    }
    const A = Ed25519_1.Point.BASE.mul(priv).toRawBytes();
    const r = (0, Math_1.RandomBigInt)();
    const R = Ed25519_1.Point.BASE.mul(r).toRawBytes();
    const to_hash2 = (0, Serialization_1.ConcatUint8Arrays)([R, A, msg]);
    const k = (0, Math_1.mod)((0, Serialization_1.BigIntFromByteArray)(await (0, Hash_1.SHA512_Digest)(to_hash2)));
    const S = (0, Math_1.mod)(r + (k * priv));
    const sig_bytes = (0, Serialization_1.ConcatUint8Arrays)([R, (0, Serialization_1.BigIntToByteArray)(S)]);
    return (0, Serialization_1.bytesToBase64)(sig_bytes);
}
/**
 * Verify a EdDSA signature, given a signature, public key and message.
 * @param {string} sig In base64
 * @param {string | Point} pub
 * @param {string | Uint8Array} msg
 * @returns Boolean dependant on whether the signature is valid or not.
 */
async function verify(sig, pub, msg) {
    try {
        if (typeof (msg) == 'string') {
            msg = (0, Serialization_1.StringToUint8Array)(msg);
        }
        const sig_bytes = (0, Serialization_1.base64ToBytes)(sig);
        if (sig_bytes.length != 64)
            return false;
        const R = Ed25519_1.Point.fromBytes(sig_bytes.slice(0, 32));
        const S = (0, Serialization_1.BigIntFromByteArray)(sig_bytes.slice(-32));
        const A = typeof (pub) === 'string' ? Ed25519_1.Point.fromBase64(pub) : pub;
        return await verifyRaw(S, R, A, msg);
    }
    catch {
        return false; // very strict indeed
    }
}
/**
 * Verify a message with raw S and R
 * @param {bigint} S
 * @param {Point} R
 * @param {Point} A
 * @param {Uint8Array} M
 */
async function verifyRaw(S, R, A, M) {
    if (S < BigInt(0) || S >= Ed25519_1.CURVE.n) {
        return false;
    }
    const to_hash = (0, Serialization_1.ConcatUint8Arrays)([R.toRawBytes(), A.toRawBytes(), M]);
    const k = (0, Math_1.mod)((0, Serialization_1.BigIntFromByteArray)(await (0, Hash_1.SHA512_Digest)(to_hash)));
    return Ed25519_1.Point.BASE.mul(S).mul(BigInt(8)).equals(R.mul(BigInt(8)).add(A.mul(k).mul(BigInt(8))));
}
