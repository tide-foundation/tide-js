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
exports.createAESKey = createAESKey;
exports.encryptData = encryptData;
exports.encryptDataRawOutput = encryptDataRawOutput;
exports.decryptData = decryptData;
exports.decryptDataRawOutput = decryptDataRawOutput;
const Serialization_1 = require("../Serialization");
const enc = new TextEncoder();
const dec = new TextDecoder();
/**
 *
 * @param {Uint8Array} rawKey
 * @param {Iterable} keyUsage
 * @returns
 */
function createAESKey(rawKey, keyUsage) {
    return window.crypto.subtle.importKey("raw", rawKey, "AES-GCM", true, keyUsage);
}
/**
 * @param {string|Uint8Array} secretData
 * @param {Uint8Array|bigint|string} key
 * @returns
 */
async function encryptData(secretData, key) {
    var aesKey;
    if (key instanceof Uint8Array) {
        aesKey = key;
    }
    else if (typeof (key) === 'string') {
        aesKey = enc.encode(key);
    }
    else if (typeof (key) === 'bigint') {
        aesKey = (0, Serialization_1.BigIntToByteArray)(key);
    }
    else {
        throw Error("Unsupported key type");
    }
    const encoded = typeof (secretData) === 'string' ? enc.encode(secretData) : secretData;
    const encrypted = await encryptDataRawOutput(encoded, aesKey);
    return (0, Serialization_1.bytesToBase64)(encrypted);
}
/**
 * @param {Uint8Array} encodedData
 * @param {Uint8Array} aesKey
 * @returns
 */
async function encryptDataRawOutput(encodedData, aesKey) {
    const cryptoKey = await createAESKey(aesKey, ["encrypt"]);
    // iv will be needed for decryption
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cryptoKey, encodedData);
    const buff = (0, Serialization_1.ConcatUint8Arrays)([iv, new Uint8Array(encryptedBuffer)]);
    return buff;
}
/**
 * @param {string} encryptedData
 * @param {Uint8Array|bigint|string} key
 * @returns
 */
async function decryptData(encryptedData, key) {
    var aesKey;
    if (key instanceof Uint8Array) {
        aesKey = key;
    }
    else if (typeof (key) === 'string') {
        aesKey = enc.encode(key);
    }
    else if (typeof (key) === 'bigint') {
        aesKey = (0, Serialization_1.BigIntToByteArray)(key);
    }
    else {
        throw Error("Unsupported key type");
    }
    const encryptedDataBuff = (0, Serialization_1.base64ToBytes)(encryptedData);
    const decryptedContent = await decryptDataRawOutput(encryptedDataBuff, aesKey);
    return dec.decode(decryptedContent);
}
/**
 * @param {Uint8Array} encryptedData
 * @param {Uint8Array} key 32 bytes
 */
async function decryptDataRawOutput(encryptedData, key) {
    const aesKey = await createAESKey(key, ["decrypt"]);
    const iv = encryptedData.slice(0, 12);
    const data = encryptedData.slice(12);
    const decryptedContent = await window.crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: iv,
    }, aesKey, data);
    return new Uint8Array(decryptedContent);
}
