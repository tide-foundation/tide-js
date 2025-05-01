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

import { ConcatUint8Arrays } from "../Serialization.js";
/**
 * @param {string|Uint8Array} message 
 * @returns 
 */
export async function SHA256_Digest(message) {
  const data = typeof (message) === 'string' ? new TextEncoder().encode(message) : message;
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);

}

/**
 * @param {string|Uint8Array} message 
 * @returns 
 */
export async function SHA512_Digest(message) {
  const data = typeof (message) === 'string' ? new TextEncoder().encode(message) : message;
  const hash = await crypto.subtle.digest('SHA-512', data);
  return new Uint8Array(hash);

}

/**
 * DO NOT USE THIS TO SIGN. THE KEY IS THE HASH OF THE FIRST MESSAGE PASSED. THIS FUNCTION IS FOR HASHING MULTIPLE MESSAGES.
 * @param {string} message
 * @param {Point} pub
 */
export async function HMAC_forHashing(message, pub){
  const tx = new TextEncoder();
  const key = await SHA256_Digest(tx.encode(message));
  const cryptoKey = await crypto.subtle.importKey(
    'raw', // raw format for Uint8Array input
    key, // the Uint8Array key data
    {
      name: 'HMAC',
      hash: { name: 'SHA-256' }, // specifying the hash algorithm to use with HMAC
    },
    false, // whether the key is extractable
    ['sign'] // allowed key usages
  );
  const hash = await window.crypto.subtle.sign("HMAC", cryptoKey, pub.toRawBytes());
  return new Uint8Array(hash);
}
