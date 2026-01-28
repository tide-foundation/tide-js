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

import { CURVE, Point } from "./Ed25519";
import { BigIntFromByteArray, BigIntToByteArray } from "../Cryptide/Serialization"
import { SHA256_Digest } from "./Hashing/Hash";
import TideKey from "./TideKey";
import { computeSharedKey, generateECDHi } from "./Encryption/DH";

const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);

/**
 * @param {bigint} a 
 * @param {bigint} b 
 * @returns {bigint}
 */
export function mod(a, b = CURVE.n) {
	var res = a % b;
	return res >= BigInt(0) ? res : b + res;
}

/**
 * 
 * @param {bigint[]} numbers 
 * @returns 
 */
export function median(numbers) {
	const sorted: any = Array.from(numbers).sort();
	const middle = Math.floor(sorted.length / 2);

	if (sorted.length % 2 === 0) {
		return ((sorted[middle - 1] + (sorted[middle])) / _2n);
	}

	return sorted[middle];
}

/**
 * @returns {bigint}
 */
export function RandomBigInt() {
	const buf = new Uint8Array(32);
	window.crypto.getRandomValues(buf);
	return mod(BigIntFromByteArray(buf), CURVE.n);
}

export function GenSessKey(){
	return BigIntToByteArray(RandomBigInt());
}
/**
 * @param {Point} gPassPRISM 
 * @returns 
 */
export async function CreateGPrismAuth(gPassPRISM){
	return Point.BASE.mul(await gPassPRISM.hash());
}

/**
 * 
 * @param {bigint | Uint8Array} a 
 */
export function GetPublic(a){
	let num = typeof(a) == 'bigint'? a : BigIntFromByteArray(a);
	return Point.BASE.mul(num);
}

/**
 * 
 * @param {number[]} arr 
 * @returns 
 */
export function Min(arr){
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
export function mod_inv(number, modulo = CURVE.n) {
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
	if (gcd !== _1n) throw new Error('invert: does not exist');
	return mod(x, modulo);
}

/**
* 
* @param {Point[]} points 
*/
export function SumPoints(points) {
	return points.reduce((sum, next) => sum.add(next));
}