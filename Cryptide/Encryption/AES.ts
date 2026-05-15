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

import { base64ToBytes, BigIntToByteArray, bytesToBase64, ConcatUint8Arrays } from "../Serialization";

const enc = new TextEncoder();
const dec = new TextDecoder();

export function createAESKey(rawKey: Uint8Array, keyUsage: KeyUsage[]) {
    return window.crypto.subtle.importKey(
        "raw",
        rawKey as unknown as BufferSource,
        "AES-GCM",
        true,
        keyUsage
    );
}

export async function encryptData(secretData: string | Uint8Array, key: Uint8Array | bigint | string) {
    var aesKey;
    if (key instanceof Uint8Array) {
        aesKey = key;
    } else if(typeof(key) === 'string'){
        aesKey = enc.encode(key);
    } else if(typeof(key) === 'bigint'){
        aesKey = BigIntToByteArray(key);
    }else{
        throw Error("Unsupported key type");
    }
    const encoded = typeof (secretData) === 'string' ? enc.encode(secretData) : secretData;
    const encrypted = await encryptDataRawOutput(encoded, aesKey);
    return bytesToBase64(encrypted);
}
export async function encryptDataRawOutput(encodedData: Uint8Array, aesKey: Uint8Array){
    const cryptoKey = await createAESKey(aesKey, ["encrypt"]);
    // iv will be needed for decryption
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        encodedData as unknown as BufferSource
    );
    const buff = ConcatUint8Arrays([iv, new Uint8Array(encryptedBuffer)]);
    return buff;
}


export async function decryptData(encryptedData: string, key: Uint8Array | bigint | string) {
    var aesKey;
    if (key instanceof Uint8Array) {
        aesKey = key;
    } else if(typeof(key) === 'string'){
        aesKey = enc.encode(key);
    } else if(typeof(key) === 'bigint'){
        aesKey = BigIntToByteArray(key);
    }
    else{
        throw Error("Unsupported key type");
    }
    const encryptedDataBuff = base64ToBytes(encryptedData);
    const decryptedContent = await decryptDataRawOutput(encryptedDataBuff, aesKey)
    return dec.decode(decryptedContent);
}

export async function decryptDataRawOutput(encryptedData: Uint8Array, key: Uint8Array){
    const aesKey = await createAESKey(key, ["decrypt"]);
    const iv = encryptedData.slice(0, 12);
    const data = encryptedData.slice(12);
    const decryptedContent = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        aesKey,
        data
    );
    return new Uint8Array(decryptedContent);
}