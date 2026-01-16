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
exports.mod = mod;
exports.median = median;
exports.RandomBigInt = RandomBigInt;
exports.GenSessKey = GenSessKey;
exports.CreateGPrismAuth = CreateGPrismAuth;
exports.GetPublic = GetPublic;
exports.Min = Min;
exports.mod_inv = mod_inv;
exports.SumPoints = SumPoints;
const Ed25519_1 = require("./Ed25519");
const Serialization_1 = require("../Cryptide/Serialization");
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
/**
 * @param {bigint} a
 * @param {bigint} b
 * @returns {bigint}
 */
function mod(a, b = Ed25519_1.CURVE.n) {
    var res = a % b;
    return res >= BigInt(0) ? res : b + res;
}
/**
 *
 * @param {bigint[]} numbers
 * @returns
 */
function median(numbers) {
    const sorted = Array.from(numbers).sort();
    const middle = Math.floor(sorted.length / 2);
    if (sorted.length % 2 === 0) {
        return ((sorted[middle - 1] + (sorted[middle])) / _2n);
    }
    return sorted[middle];
}
/**
 * @returns {bigint}
 */
function RandomBigInt() {
    const buf = new Uint8Array(32);
    window.crypto.getRandomValues(buf);
    return mod((0, Serialization_1.BigIntFromByteArray)(buf), Ed25519_1.CURVE.n);
}
function GenSessKey() {
    return (0, Serialization_1.BigIntToByteArray)(RandomBigInt());
}
/**
 * @param {Point} gPassPRISM
 * @returns
 */
async function CreateGPrismAuth(gPassPRISM) {
    return Ed25519_1.Point.BASE.mul(await gPassPRISM.hash());
}
/**
 *
 * @param {bigint | Uint8Array} a
 */
function GetPublic(a) {
    let num = typeof (a) == 'bigint' ? a : (0, Serialization_1.BigIntFromByteArray)(a);
    return Ed25519_1.Point.BASE.mul(num);
}
/**
 *
 * @param {number[]} arr
 * @returns
 */
function Min(arr) {
    let minValue = arr[0]; // Initialize with the first element
    for (let i = 1; i < arr.length; i++) {
        if (arr[i] < minValue) {
            minValue = arr[i];
        }
    }
    return minValue;
}
/**
 * @param {bigint} number
 * @param {bigint} modulo
 * @returns {bigint}
 */
function mod_inv(number, modulo = Ed25519_1.CURVE.n) {
    if (number === _0n || modulo <= _0n) {
        throw new Error(`invert: expected positive integers, got n=${number} mod=${modulo}`);
    }
    let a = mod(number, modulo);
    let b = modulo;
    // prettier-ignore
    let x = _0n, y = _1n, u = _1n, v = _0n;
    while (a !== _0n) {
        const q = b / a;
        const r = b % a;
        const m = x - u * q;
        const n = y - v * q;
        // prettier-ignore
        b = a, a = r, x = u, y = v, u = m, v = n;
    }
    const gcd = b;
    if (gcd !== _1n)
        throw new Error('invert: does not exist');
    return mod(x, modulo);
}
/**
*
* @param {Point[]} points
*/
function SumPoints(points) {
    return points.reduce((sum, next) => sum.add(next));
}
