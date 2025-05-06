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

import GenShardResponse from "../Models/Responses/KeyGen/GenShard/GenShardResponse.js";
import SetShardResponse from "../Models/Responses/KeyGen/SetShard/SetShardResponse.js";
import { SHA256_Digest } from "../Cryptide/Hashing/Hash.js";
import { AES, EdDSA, Interpolation, Math, Serialization, ElGamal } from "../Cryptide/index.js";
import DecryptedGenShardResponse from "../Models/Responses/KeyGen/GenShard/DecryptedGenShardResponse.js";
import DecryptedSetShardResponse from "../Models/Responses/KeyGen/SetShard/DecryptedSetShardResponse.js";
import AuthRequest from "../Models/AuthRequest.js";
import { AuthorizerPack, BigIntToByteArray, Bytes2Hex, ConcatUint8Arrays, GVRK_Pack, Hex2Bytes, StringFromUint8Array, StringToUint8Array, base64ToBytes, bytesToBase64, serializeBitArray, uint8ArrayToBitArray } from "../Cryptide/Serialization.js";
import { mod } from "../Cryptide/Math.js";
import { Max } from "../Tools/Utils.js";
import { CreateAuthorizerPackage, CreateVRKPackage } from "../Cryptide/TideMemoryObjects.js";
import { Point } from "../Cryptide/Ed25519.js";
/**
* @param {GenShardResponse[]} responses Can be T amount
* @param {(0 | 1)[]} bitwise
* @param {Uint8Array} sessKey
* @param {boolean} vrkSigning
*/
export async function ProcessShards(responses, bitwise, sessKey, vrkSigning=false){
    const sortedShares = SortShares(responses.map(resp => resp.YijCiphers), bitwise); // sort shares so they can easily be sent to respective orks  
    const pre_decryptedResponses = responses.map(async (resp) => DecryptedGenShardResponse.from(StringFromUint8Array(await ElGamal.decryptData(resp.EncReply, sessKey))));
    const decryptedResponses = await Promise.all(pre_decryptedResponses);

    const gMultiplied = Interpolation.AggregatePublicComponentArrays(decryptedResponses.map(resp => resp.GMultiplied));
    const gR = Interpolation.AggregatePoints(decryptedResponses.map(resp => resp.GRi));
    const gK = Interpolation.AggregatePublicComponents(decryptedResponses.map(resp => resp.GK1i))?.public;
    const timestamp = Math.median(decryptedResponses.map(resp => resp.Timestampi));
    const VRK_gR = vrkSigning ? Interpolation.AggregatePointArrays(decryptedResponses.map(resp => resp.VRK_GR)) : null;

    return {gMultiplied, gR, gK, timestamp, sortedShares, VRK_gR};
}

/**
 * @param {string} keyId
 * @param {SetShardResponse[]} sendShardResponses
 * @param {Point[]} mgORKi 
 * @param {bigint} timestamp
 * @param {Point} R
 * @param {Point} gK1
 * @param {(0|1)[]} participatingBitwise
 * @param {string} purpose
 * @param {Uint8Array} sessKey
 * @param {Point} gSessKeyPub
 * @param {Point[] | null} vrk_gR
 * @param {string | null} authorizer_package
 */
export async function CommitShardPrep(keyId, sendShardResponses, mgORKi, timestamp, R, gK1, participatingBitwise, purpose, sessKey, gSessKeyPub, vrk_gR=null, authorizer_package=null){
    // Decrypt Responses
    const pre_decryptedResponses = sendShardResponses.filter(resp => resp.EncSi != '').map(async (resp) => DecryptedSetShardResponse.from(StringFromUint8Array(await ElGamal.decryptData(resp.EncSi, sessKey))));
    const decryptedResponses = await Promise.all(pre_decryptedResponses);

    // Verify VRK if requested
    let main_vrkSignatureToStore = new Uint8Array();
    let firstAdmin_vrkSignatureToStore = new Uint8Array();
    let firstAdmin_gvrk_ToStore = "";
    if(vrk_gR != null && authorizer_package != null){
        const VRK_S_MainVRK = mod(decryptedResponses.reduce((sum, next) =>  next.VRK_Si[0] + sum, BigInt(0)));
        // THROW ERROR IF SIG FAILS - MEANS VVK HAS NO AUTHORITY AND IS TRULY A GANGSTA

        const main_vrk_valid = await EdDSA.verifyRaw(VRK_S_MainVRK, vrk_gR[0], gK1, Hex2Bytes(authorizer_package));
        if(!main_vrk_valid) throw Error("Main VRK validation failed");

        main_vrkSignatureToStore = ConcatUint8Arrays([vrk_gR[0].toRawBytes(), BigIntToByteArray(VRK_S_MainVRK)]);

        // First admin VRK sig verification -----
        // Construct firstAdmin VRK from MainVRK
        const mainAuthPack = new AuthorizerPack(Hex2Bytes(authorizer_package));
        const first_admin_vrk = CreateVRKPackage(mainAuthPack.Authorizer.GVRK, timestamp + BigInt(432000)); // quick expiry
        const first_admin_authorizer = CreateAuthorizerPackage("VRK:1", ["UserContext:1"], first_admin_vrk);

        const VRK_S_FirstAdmin = mod(decryptedResponses.reduce((sum, next) =>  next.VRK_Si[1] + sum, BigInt(0)));
        const firstAdmin_vrk_valid = await EdDSA.verifyRaw(VRK_S_FirstAdmin, vrk_gR[1], gK1, first_admin_authorizer);
        if(!firstAdmin_vrk_valid) throw Error("First Admin VRK validation failed");

        firstAdmin_vrkSignatureToStore = ConcatUint8Arrays([vrk_gR[1].toRawBytes(), BigIntToByteArray(VRK_S_FirstAdmin)]);
        firstAdmin_gvrk_ToStore = Bytes2Hex(first_admin_authorizer);
    }

    // Aggregate the signature
    const S = mod(decryptedResponses.reduce((sum, next) =>  next.Si + sum, BigInt(0)));

    // Prepare the signature message
    const permissionMessage = AuthRequest.new(keyId, purpose, gSessKeyPub.toBase64(), timestamp + BigInt(30));

    const M_data_to_hash = ConcatUint8Arrays([serializeBitArray(participatingBitwise), permissionMessage.toUint8Array()]);
    const M = await SHA256_Digest(M_data_to_hash);
    const mgORKs = mgORKi.reduce((sum, next, i) => participatingBitwise[i] == true ? sum.add(next) : sum, Point.ZERO);

    const accountableKey = gK1.add(mgORKs);

    // Verify signature validates
    const valid = await EdDSA.verifyRaw(S, R, accountableKey, M);
    if(!valid) throw new Error("SetShard: Signature test failed");

    return {
        S: S, 
        gR: R, 
        gSessKeyPub, 
        M, 
        vrkSignatureToStore: main_vrkSignatureToStore,
        firstAdmin: {
            authorizer: firstAdmin_gvrk_ToStore,
            certificate : firstAdmin_vrkSignatureToStore
        }
    };
}

/**
 * @param {string[][]} sharesEncrypted L1 can be T long, L2 will be N long
 * @param {(0 | 1)[]} bitwise
 * @returns {string[][]}
 */
function SortShares(sharesEncrypted, bitwise) {
    // assert all L2 arrays are the same legnth
    if(!sharesEncrypted.every(l1 => l1.length == Max)) throw Error("Not all orks returned the correct amount of YijCiphers");

    let easyToUnderstandShares = [];
    let inputIndex = 0;
    for(let i = 0; i < bitwise.length; i++){
        if(bitwise[i] == 0){
            easyToUnderstandShares.push(Array(Max).fill("unavailable"));
        }else{
            easyToUnderstandShares.push(sharesEncrypted[inputIndex]);
            inputIndex++;
        }
    }

    let sorted = easyToUnderstandShares.map((_, i) => easyToUnderstandShares.map(share => share[i]));
    let sortedCleaned = [];
    for(let i = 0; i < bitwise.length; i++){
        if(bitwise[i] == 1) sortedCleaned.push(sorted[i]);
    }

    return sortedCleaned;
}
