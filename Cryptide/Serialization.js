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

import { CurrentTime } from "../Tools/Utils.js";
import { Ed25519PublicComponent } from "./Components/Schemes/Ed25519/Ed25519Components.js";
import Point from "./Ed25519.js";
import { SHA256_Digest } from "./Hashing/Hash.js";
import { EdDSA } from "./index.js";
import { CreateVRKPackage } from "./TideMemoryObjects.js";

/**
 * 
 * @param {BigInt} value 
 * @returns 
 */
export function writeInt64LittleEndian(value) {
    const INT64_MIN = -9223372036854775808n; // -2^63
    const INT64_MAX = 9223372036854775807n;  // 2^63 - 1

    if (value < INT64_MIN || value > INT64_MAX) {
        throw new RangeError("Value is out of range for a 64-bit signed integer.");
    }

    const bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        bytes[i] = Number((value >> BigInt(8 * i)) & 0xFFn);
    }

    return bytes;
}
/**
 * 
 * @param {Uint8Array} bytes 
 * @returns 
 */
export function readInt64LittleEndian(bytes) {
    if (bytes.length !== 8) {
        throw new Error("Invalid byte array length. Expected 8 bytes.");
    }

    let value = 0n;
    for (let i = 0; i < 8; i++) {
        value |= BigInt(bytes[i]) << BigInt(8 * i);
    }

    // Interpret the value as a signed 64-bit integer
    value = BigInt.asIntN(64, value);

    return value;
}
export class AuthorizerPack{
	constructor(data){
		if(!(data instanceof Uint8Array)) throw Error("Data must be byte array");
		this.AuthFlow = StringFromUint8Array(GetValue(data, 0));
		this.Authorizer = new GVRK_Pack(GetValue(data, 1));
		
		var c = true;
		var i = 2;
		this.SignModels = [];
		while(c){
			try{this.SignModels.push(StringFromUint8Array(GetValue(data, i)));i++;}
			catch{c = false;}
		}
	}
}
export class GVRK_Pack{
	constructor(data){
        /** @type {Ed25519PublicComponent} */
		this.GVRK = Ed25519PublicComponent.DeserializeComponent(GetValue(data, 0));
		this.Expiry = readInt64LittleEndian(GetValue(data, 1)); // we do not allow vrks without expiry on enclave for now
	}
    encode(){
        return CreateVRKPackage(this.GVRK, this.Expiry);
    }
}
/**
 * 
 * @param {Uint8Array} initialValue 
 * @param {number} totalLength 
 * @param {number} version 
 * @returns 
 */
export function CreateTideMemory(initialValue, totalLength, version = 1) {
    if (totalLength < initialValue.length + 4) {
        throw new Error("Not enough space to allocate requested data. Make sure to request more space in totalLength than length of InitialValue plus 4 bytes for length.");
    }

    // Total buffer length is 4 (version) + totalLength
    const bufferLength = 4 + totalLength;
    const buffer = new Uint8Array(bufferLength);
    const dataView = new DataView(buffer.buffer);

    // Write version at position 0 (4 bytes)
    dataView.setInt32(0, version, true); // true for little-endian

    let dataLocationIndex = 4;

    // Write data length of initialValue at position 4 (4 bytes)
    dataView.setInt32(dataLocationIndex, initialValue.length, true);
    dataLocationIndex += 4;

    // Write initialValue starting from position 8
    buffer.set(initialValue, dataLocationIndex);

    return buffer;
}
/**
 * 
 * @param {Uint8Array} memory 
 * @param {number} index 
 * @param {Uint8Array} value 
 */
export function WriteValue(memory, index, value) {
    if (index < 0) throw new Error("Index cannot be less than 0");
    if (index === 0) throw new Error("Use CreateTideMemory to set value at index 0");
    if (memory.length < 4 + value.length) throw new Error("Could not write to memory. Memory too small for this value");

    const dataView = new DataView(memory.buffer);
    let dataLocationIndex = 4; // Start after the version number

    // Navigate through existing data segments
    for (let i = 0; i < index; i++) {
        if (dataLocationIndex + 4 > memory.length) {
            throw new RangeError("Index out of range.");
        }

        // Read data length at current position
        const nextDataLength = dataView.getInt32(dataLocationIndex, true);
        dataLocationIndex += 4;

        dataLocationIndex += nextDataLength;
    }

    // Check if there's enough space to write the value
    if (dataLocationIndex + 4 + value.length > memory.length) {
        throw new RangeError("Not enough space to write value");
    }

    // Check if data has already been written to this index
    const existingLength = dataView.getInt32(dataLocationIndex, true);
    if (existingLength !== 0) {
        throw new Error("Data has already been written to this index");
    }

    // Write data length of value at current position
    dataView.setInt32(dataLocationIndex, value.length, true);
    dataLocationIndex += 4;

    // Write value starting from current position
    memory.set(value, dataLocationIndex);
}
/**
 * 
 * @param {Uint8Array} a 
 * @param {number} index 
 * @returns 
 */
export function GetValue(a, index) {
    // 'a' should be an ArrayBuffer or Uint8Array
    let buffer;
    if (a instanceof Uint8Array) {
        buffer = a;
    } else {
        throw new TypeError("Input must be an Uint8Array.");
    }

    if (buffer.length < 4) {
        throw new Error("Insufficient data to read.");
    }

    // Create a DataView for reading integers in little-endian format
    const dataView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

    // Optional: Read the version if needed
    // const version = dataView.getInt32(0, true);

    let dataLocationIndex = 4;

    for (let i = 0; i < index; i++) {
        // Check if there's enough data to read the length of the next segment
        if (dataLocationIndex + 4 > buffer.length) {
            throw new RangeError("Index out of range.");
        }

        const nextDataLength = dataView.getInt32(dataLocationIndex, true);
        dataLocationIndex += 4 + nextDataLength;
    }

    // Check if there's enough data to read the length of the final segment
    if (dataLocationIndex + 4 > buffer.length) {
        throw new RangeError("Index out of range.");
    }

    const finalDataLength = dataView.getInt32(dataLocationIndex, true);
    dataLocationIndex += 4;

    // Check if the final data segment is within bounds
    if (dataLocationIndex + finalDataLength > buffer.length) {
        throw new RangeError("Index out of range.");
    }

    return buffer.subarray(dataLocationIndex, dataLocationIndex + finalDataLength);
}

export function TryGetValue(a, index, returnObj){
	try{
		returnObj = GetValue(a, index);
		return true;
	}catch{
		returnObj = null;
		return false;
	}

}

export function DeserializeNetworkKey(data){
	return Point.from(Hex2Bytes(data.toLowerCase()));
}

/**
 * 
 * @param {Point} p 
 */
export async function EdPointToJWK(p){
	return JSON.stringify({
		"kty": "OKP",
		"kid": Bytes2Hex(await SHA256_Digest(p.toArray())),
		"alg": "EdDSA",
		"crv": "Ed25519",
		"x": base64ToBase64Url(p.toBase64())
	});
}

/**
 * 
 * @param {string} key 
 * @param {string} prefix 
 */
export function DeserializeTIDE_KEY(key, prefix){
	const header = key.substring(0, 8);
	const data = base64ToBytes(key.substring(8, key.length));
	if(header != "tide" + prefix + "key") throw Error("Unexpected header in deserialization");
	if(data.length != 32) throw Error("Unexpected key length in deserialization");
	return BigIntFromByteArray(data);
}

export async function GetUID(str){
	return Bytes2Hex(await SHA256_Digest(str.toLowerCase()));
}

/**
 * @param {BigInt} num 
 * @returns {Uint8Array}
 */
export function BigIntToByteArray(num) {
	const hex = num.toString(16).padStart(32 * 2, '0');
	return Hex2Bytes(hex).reverse();
}

/**
 * @param {Uint8Array} bytes 
 * @returns {bigint}
 */
export function BigIntFromByteArray(bytes) {
	const b = bytes.slice();
	const hex = Bytes2Hex(b.reverse());
	return BigInt("0x" + hex);
}

/**
 * 
 * @param {Uint8Array[]} arrays 
 */
export function ConcatUint8Arrays(arrays) {
	const totalLength = arrays.reduce((sum, next) => next.length + sum, 0);
	var newArray = new Uint8Array(totalLength);
	var offset = 0;
	arrays.forEach(item => {
		newArray.set(item, offset);
		offset += item.length;
	});
	return newArray;
}

/**
 * @param {Uint8Array} array1 
 * @param {Uint8Array} array2 
 */
export function XOR(array1, array2){
	if (array1.length !== array2.length) {
        throw new Error('Arrays have different lengths, cannot XOR them.');
    }
    let result = new Uint8Array(array1.length);
    for (let i = 0; i < array1.length; i++) {
        result[i] = array1[i] ^ array2[i];
    }
    return result;
}
/**
 * 
 * @param {Array} array 
 * @param {number} length 
 * @param {object} padding 
 * @returns 
 */
export function PadRight(array, length, padding=0) {
    while (array.length < length) {
        array.push(padding);
    }
    return array;
}

/**
 * @param {string} string 
 */
export function StringToUint8Array(string) {
	const enc = new TextEncoder();
	return enc.encode(string);
}

/**
 * @param {Uint8Array} bytes 
 */
export function StringFromUint8Array(bytes){
	const decoder = new TextDecoder('utf-8');
    return decoder.decode(bytes);
}

export class Byte {
    constructor() {
		/**
		 * @type {number[]}
		 */
        this.bits = []; // bits.length should never exceed 8 - hence a byte
    }
	/**
	 * Sets a bit at the start of the array (index 0)
	 * @param {number} bit 
	 */
	setFirstBit(bit){
		const b = bit === 0 ? 0 : 1;
		this.bits[0] = b;
	}
	/**
	 * @returns {Uint8Array}
	 */
    toUint8Array() {
		let number = 0;
		for (let i = 0; i < 8; i++) {
			number += this.bits[i] * Math.pow(2, 7 - i); 
		}
	
		const byteArray = new Uint8Array(1); // only 1 byte needed
		byteArray[0] = number & 255; 
		
		return byteArray;
	}

	/**
	 * @param {Uint8Array} uint8Array 
	 * @returns {Byte}
	 */
    static fromUint8Array(uint8Array) {
        let bitArray = new Byte();
		for (let i = 7; i >= 0; i--) {
			bitArray.bits.push((uint8Array[0] >> i) & 1); // only get first byte of byte array
		}
        return bitArray;
    }
	/**
	 * Maximum number of 255
	 * @param {number} number 
	 * @returns {Byte}
	 */
	static fromNumber(number) {
		if (number < 0 || number > 255) {
			throw Error("Number must be between 0 and 255"); // Adjusted the range check
		}
		let byte = new Byte();
		let binaryString = number.toString(2).padStart(8, '0'); // Pad the string to ensure 8 bits
		for (let i = 0; i < 8; i++) {
			byte.bits.push(binaryString[i] === '1' ? 1 : 0); // Corrected the condition
		}
		return byte;
	}
}
export function getBytesFromInt16(schemeInt) {
    // Create an ArrayBuffer with 2 bytes (16 bits)
    const buffer = new ArrayBuffer(2);
    const view = new DataView(buffer);
    // Write the 16-bit integer to the buffer, little-endian
    view.setInt16(0, schemeInt, true); // 'true' for little-endian, 'false' for big-endian
    // Return the bytes as a Uint8Array
    return new Uint8Array(buffer);
}
/**
 * @param {number} num 
 * @param {number} len Length of bytes requested
 * @returns 
 */
export function numberToUint8Array(num, len=-1) {
	if (num < 0 || !Number.isInteger(num)) {
        throw new Error('Number must be a non-negative integer.');
    }

    if (num === 0) return new Uint8Array([0]);

    let numberOfBytes = Math.ceil(Math.log2(num + 1) / 8);
    let byteArray = new Uint8Array(numberOfBytes);

    for (let i = 0; i < numberOfBytes; i++) {
        byteArray[i] = (num >> (8 * i)) & 0xFF;
    }
	if(len == -1) return byteArray;
	else{
		const offset = len - byteArray.length;
		if(offset == 0) return byteArray;
		const padding = new Uint8Array(offset).fill(0);
		return ConcatUint8Arrays([byteArray, padding]);
	}
}
/**
 * @param {Uint8Array} array 
 */
export function Uint8ArrayToNumber(byteArray){
	if (!(byteArray instanceof Uint8Array)) {
        throw new Error('Input must be a Uint8Array.');
    }

    let num = 0;
    for (let i = byteArray.length - 1; i >= 0; i--) {
        num = (num << 8) | byteArray[i];
    }
    return num;
}
/**
 * @param {string} base64 
 * @returns 
 */
export function base64ToBase64Url(base64) {
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** 
 * @param {string} base64Url 
 * @returns 
 */
export function base64UrlToBase64(base64Url) {
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    return base64;
}

/**
 * @param {number[]} array 
 * @returns 
 */
export function bitArrayToUint8Array(array) {
	// Made without ChatGPT (but had some help)
	const byteArray = new Uint8Array(Math.ceil(array.length/8));
	let bitCount = 0;
	for(let i = 0; i < byteArray.length; i++){
		const currentByteLength = array.length - bitCount >= 8 ? 8 : array.length - bitCount;
		for (let j = 0; j < currentByteLength; j++) {
			byteArray[i] |= array[bitCount] << (currentByteLength - 1 - j);
			bitCount++;
		}
	}
    
    return byteArray;
}
/**
 * Works for .NET functions.
 * @param {number[]} array 
 * @returns 
 */
export function serializeBitArray(bitArray_p) { 
	// If anyone does a deep dive into this function and notices the bits are reversed, blame .NET's BitArray class.
	let bitArray = bitArray_p.slice();
    // Ensure the bit array length is a multiple of 8 by padding if necessary
    while (bitArray.length % 8 !== 0) {
        bitArray.push(0);
    }

    const byteArray = new Uint8Array(bitArray.length / 8);

    for (let byteIndex = 0; byteIndex < byteArray.length; byteIndex++) {
        // For each byte, calculate its value from 8 bits, reversing the bit order
        let byteValue = 0;
        for (let bitPosition = 0; bitPosition < 8; bitPosition++) {
            byteValue |= (bitArray[byteIndex * 8 + bitPosition] << bitPosition);
        }
        byteArray[byteIndex] = byteValue;
    }

    return byteArray;
}
/**
 * 
 * @param {(0|1)[]} bitarray1 
 * @param {(0|1)[]} bitarray2 
 * @returns 
 */
export function bitArrayAND(bitarray1, bitarray2){
	return bitarray1.map((b, i) => b == 1 && bitarray2[i] == 1 ? 1 : 0)
}
/**
 * Works for .NET functions.
 * @param {Uint8Array} byteArray 
 * @returns 
 */
export function deserializeBitArray(byteArray) {
    const bitArray = [];

    byteArray.forEach(byte => {
        for (let bitPosition = 0; bitPosition < 8; bitPosition++) {
            bitArray.push((byte >> bitPosition) & 1);
        }
    });

    // Remove padding
    while (bitArray.length > 0 && bitArray[bitArray.length - 1] === 0) {
        bitArray.pop();
    }

    return bitArray;
}
export function uint8ArrayToBitArray(byteArray) {
    // always produces a bitArray of length 20
    const bitArray = [];
    let count = 0;
    for (let i = 0; i < byteArray.length; i++) {
        for (let j = 7; j >= 0; j--) {
            // Extract the j-th bit of the i-th byte.
            const bit = (byteArray[i] >> j) & 1;
            if(count < 16 || count > 19) bitArray.push(bit); // exclude intermediate bits, always l=20!
            count++;
        }
    }
    
    return bitArray;
}
/**
 * @param {string} string 
 * @returns {Uint8Array}
 */
export function Hex2Bytes(string) {
    const hexRegex = /^0x[0-9A-Fa-f]+$|^[0-9A-Fa-f]+$/;
    if (!hexRegex.test(string)) throw Error("Invalid Hex");

    const normal = string.length % 2 ? "0" + string : string; // Make even length
    const bytes = new Uint8Array(normal.length / 2);

    for (let index = 0; index < bytes.length; ++index) {
        const c1 = normal.charCodeAt(index * 2);
        const c2 = normal.charCodeAt(index * 2 + 1);

        const n1 = c1 - (c1 < 58 ? 48 : (c1 < 97 ? 55 : 87));
        const n2 = c2 - (c2 < 58 ? 48 : (c2 < 97 ? 55 : 87));

        bytes[index] = n1 * 16 + n2;
    }
    return bytes;
}

/**
 * @param {Uint8Array} byteArray 
 * @returns {string}
 */
export function Bytes2Hex(byteArray) {
	const chars = new Uint8Array(byteArray.length * 2);
	const alpha = 'a'.charCodeAt(0) - 10;
	const digit = '0'.charCodeAt(0);

	let p = 0;
	for (let i = 0; i < byteArray.length; i++) {
		let nibble = byteArray[i] >>> 4;
		chars[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
		nibble = byteArray[i] & 0xF;
		chars[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
	}
	return String.fromCharCode.apply(null, chars);
}

/**
 * Credits to Egor Nepomnyaschih for the below code
 * Link: https://gist.github.com/enepomnyaschih/72c423f727d395eeaa09697058238727
*/
const base64abc = [
	"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
	"N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
	"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
	"n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"
];

const base64codes = [
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 0, 255, 255,
	255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
	255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
];

function getBase64Code(charCode) {
	if (charCode >= base64codes.length) {
		throw new Error("Unable to parse base64 string.");
	}
	const code = base64codes[charCode];
	if (code === 255) {
		throw new Error("Unable to parse base64 string.");
	}
	return code;
}

/**
 * @param {Uint8Array} bytes 
 * @returns {string}
 */
export function bytesToBase64(bytes) {
	let result = '', i, l = bytes.length;
	for (i = 2; i < l; i += 3) {
		result += base64abc[bytes[i - 2] >> 2];
		result += base64abc[((bytes[i - 2] & 0x03) << 4) | (bytes[i - 1] >> 4)];
		result += base64abc[((bytes[i - 1] & 0x0F) << 2) | (bytes[i] >> 6)];
		result += base64abc[bytes[i] & 0x3F];
	}
	if (i === l + 1) { // 1 octet yet to write
		result += base64abc[bytes[i - 2] >> 2];
		result += base64abc[(bytes[i - 2] & 0x03) << 4];
		result += "==";
	}
	if (i === l) { // 2 octets yet to write
		result += base64abc[bytes[i - 2] >> 2];
		result += base64abc[((bytes[i - 2] & 0x03) << 4) | (bytes[i - 1] >> 4)];
		result += base64abc[(bytes[i - 1] & 0x0F) << 2];
		result += "=";
	}
	return result;
}

/**
 * @param {string} str 
 * @returns {Uint8Array}
 */
export function base64ToBytes(str) {
	const base64Regex = /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/;
    if(!base64Regex.test(str)) throw Error("Not valid base64");
	if (str.length % 4 !== 0) {
		throw new Error("Unable to parse base64 string.");
	}
	const index = str.indexOf("=");
	if (index !== -1 && index < str.length - 2) {
		throw new Error("Unable to parse base64 string.");
	}
	let missingOctets = str.endsWith("==") ? 2 : str.endsWith("=") ? 1 : 0,
		n = str.length,
		result = new Uint8Array(3 * (n / 4)),
		buffer;
	for (let i = 0, j = 0; i < n; i += 4, j += 3) {
		buffer =
			getBase64Code(str.charCodeAt(i)) << 18 |
			getBase64Code(str.charCodeAt(i + 1)) << 12 |
			getBase64Code(str.charCodeAt(i + 2)) << 6 |
			getBase64Code(str.charCodeAt(i + 3));
		result[j] = buffer >> 16;
		result[j + 1] = (buffer >> 8) & 0xFF;
		result[j + 2] = buffer & 0xFF;
	}
	return result.subarray(0, result.length - missingOctets);
}


// Custom extensions

