import { Point } from "./Ed25519";
/**
 *
 * @param {BigInt} value
 * @returns
 */
export declare function writeInt64LittleEndian(value: any): Uint8Array<ArrayBuffer>;
/**
 *
 * @param {Uint8Array} bytes
 * @returns
 */
export declare function readInt64LittleEndian(bytes: any): bigint;
export declare class AuthorizerPack {
    constructor(data: any);
}
export declare class GVRK_Pack {
    constructor(data: any);
    encode(): Uint8Array<any>;
}
/**
 *
 * @param {Uint8Array} initialValue
 * @param {number} totalLength
 * @param {number} version
 * @returns
 */
export declare function CreateTideMemory(initialValue: any, totalLength: any, version?: number): Uint8Array<any>;
/**
 * @param {Uint8Array[]} datas
 */
export declare function CreateTideMemoryFromArray(datas: any): Uint8Array<any>;
/**
 *
 * @param {Uint8Array} memory
 * @param {number} index
 * @param {Uint8Array} value
 */
export declare function WriteValue(memory: any, index: any, value: any): void;
/**
 *
 * @param {Uint8Array} a
 * @param {number} index
 * @returns
 */
export declare function GetValue(a: any, index: any): Uint8Array<ArrayBufferLike>;
export declare function TryGetValue(a: any, index: any, returnObj: any): boolean;
export declare function DeserializeNetworkKey(data: any): Point;
/**
 *
 * @param {Point} p
 */
export declare function EdPointToJWK(p: any): Promise<string>;
/**
 *
 * @param {string} key
 * @param {string} prefix
 */
export declare function DeserializeTIDE_KEY(key: any, prefix: any): bigint;
export declare function GetUID(str: any): Promise<any>;
/**
 * @param {BigInt} num
 * @returns {Uint8Array}
 */
export declare function BigIntToByteArray(num: any): Uint8Array<any>;
/**
 * @param {Uint8Array} bytes
 * @returns {bigint}
 */
export declare function BigIntFromByteArray(bytes: any): bigint;
/**
 *
 * @param {Uint8Array[]} arrays
 */
export declare function ConcatUint8Arrays(arrays: any): Uint8Array<any>;
/**
 * @param {Uint8Array} array1
 * @param {Uint8Array} array2
 */
export declare function XOR(array1: any, array2: any): Uint8Array<any>;
/**
 *
 * @param {Array} array
 * @param {number} length
 * @param {object} padding
 * @returns
 */
export declare function PadRight(array: any, length: any, padding?: number): any;
/**
 * @param {string} string
 */
export declare function StringToUint8Array(string: any): Uint8Array<ArrayBuffer>;
/**
 * @param {Uint8Array} bytes
 */
export declare function StringFromUint8Array(bytes: any): string;
export declare class Byte {
    constructor();
    /**
     * Sets a bit at the start of the array (index 0)
     * @param {number} bit
     */
    setFirstBit(bit: any): void;
    /**
     * @returns {Uint8Array}
     */
    toUint8Array(): Uint8Array<ArrayBuffer>;
    /**
     * @param {Uint8Array} uint8Array
     * @returns {Byte}
     */
    static fromUint8Array(uint8Array: any): Byte;
    /**
     * Maximum number of 255
     * @param {number} number
     * @returns {Byte}
     */
    static fromNumber(number: any): Byte;
}
export declare function getBytesFromInt16(schemeInt: any): Uint8Array<ArrayBuffer>;
/**
 * @param {number} num
 * @param {number} len Length of bytes requested
 * @returns
 */
export declare function numberToUint8Array(num: any, len?: number): Uint8Array<any>;
/**
 * @param {Uint8Array} array
 */
export declare function Uint8ArrayToNumber(byteArray: any): number;
/**
 * @param {string} base64
 * @returns
 */
export declare function base64ToBase64Url(base64: any): any;
/**
 * @param {string} base64Url
 * @returns
 */
export declare function base64UrlToBase64(base64Url: any): any;
/**
 * @param {number[]} array
 * @returns
 */
export declare function bitArrayToUint8Array(array: any): Uint8Array<ArrayBuffer>;
/**
 * Works for .NET functions.
 * @param {number[]} array
 * @returns
 */
export declare function serializeBitArray(bitArray_p: any): Uint8Array<ArrayBuffer>;
/**
 *
 * @param {(0|1)[]} bitarray1
 * @param {(0|1)[]} bitarray2
 * @returns
 */
export declare function bitArrayAND(bitarray1: any, bitarray2: any): any;
/**
 * Works for .NET functions.
 * @param {Uint8Array} byteArray
 * @returns
 */
export declare function deserializeBitArray(byteArray: any): any[];
export declare function uint8ArrayToBitArray(byteArray: any): any[];
/**
 * @param {string} string
 * @returns {Uint8Array}
 */
export declare function Hex2Bytes(string: any): Uint8Array<ArrayBuffer>;
/**
 * @param {Uint8Array} byteArray
 * @returns {string}
 */
export declare function Bytes2Hex(byteArray: any): any;
/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export declare function bytesToBase64(bytes: any): string;
/**
 * @param {string} str
 * @returns {Uint8Array}
 */
export declare function base64ToBytes(str: any): Uint8Array<ArrayBuffer>;
