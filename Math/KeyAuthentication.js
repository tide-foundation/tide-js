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


import { HMAC_forHashing, SHA256_Digest, SHA512_Digest } from "../Cryptide/Hashing/Hash.js";
import { CurrentTime, randBetween } from "../Tools/Utils.js";
import { ConcatUint8Arrays, Bytes2Hex, bytesToBase64, BigIntFromByteArray, StringToUint8Array, StringFromUint8Array } from "../Cryptide/Serialization.js";
import { Min, median, mod, mod_inv } from "../Cryptide/Math.js";
import PrismConvertResponse from "../Models/Responses/KeyAuth/Convert/PrismConvertResponse.js";
import { AES, DH, EdDSA, ElGamal, Hash, Interpolation, Math } from "../Cryptide/index.js";
import DecryptedCMKConvertResponse from "../Models/Responses/KeyAuth/Convert/DecryptedCMKConvertResponse.js";
import CMKConvertResponse from "../Models/Responses/KeyAuth/Convert/CMKConvertResponse.js";
import DecryptedPrismConvertResponse from "../Models/Responses/KeyAuth/Convert/DecryptedPrismConvertResponse.js";
import AuthRequest from "../Models/AuthRequest.js";
import { genBlindMessage, serializeBlindSig, unblindSignature, verifyBlindSignature } from "../Cryptide/Signing/BlindSig.js";
import AuthenticateResponse from "../Models/Responses/KeyAuth/Authenticate/AuthenticateResponse.js";
import DecryptedConvertRememberedResponse from "../Models/Responses/KeyAuth/Convert/DecryptedConvertRememberedResponse.js";
import ConvertRememberedResponse from "../Models/Responses/KeyAuth/Convert/ConvertRememberedResponse.js";
import VendorData from "../Models/VendorData.js";
import { Point } from "../Cryptide/Ed25519.js";
import { Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import DeviceConvertResponse from "../Models/Responses/KeyAuth/Convert/DeviceConvertResponse.js";
import DecryptedDeviceConvertResponse from "../Models/Responses/KeyAuth/Convert/DecryptedDeviceConvertResponse.js";
import TideKey from "../Cryptide/TideKey.js";
import { BaseComponent } from "../Cryptide/Components/BaseComponent.js";
/**
 * For use in change password flow
 * @param {PrismConvertResponse[]} convertResponses 
 * @param {bigint[]} lis 
 * @param {Point[]} mgORKi 
 * @param {bigint} r1 
 * @returns 
 */
export async function GetDecryptedChallenge(convertResponses, lis, mgORKi, r1){
    const gPassPRISM = convertResponses.reduce((sum, next, i) => sum.add(next.GBlurPassPrismi.mul(lis[i])), Point.ZERO).mul(mod_inv(r1));
    const gPassPRISM_hashed = mod(BigIntFromByteArray(await SHA256_Digest(gPassPRISM.toRawBytes())));

    const pre_prismAuthi = mgORKi.map(async ork => await SHA256_Digest(ork.mul(gPassPRISM_hashed).toRawBytes())) // create a prismAuthi for each ork
    const prismAuthis = await Promise.all(pre_prismAuthi); // wait for all async functions to finish

    let decryptedChallenges;
    try{
        const pre_decData = convertResponses.map(async (resp, i) => await AES.decryptData(resp.EncChallengei, prismAuthis[i]));
        decryptedChallenges = await Promise.all(pre_decData);
    }catch{
        throw Error("enclave.invalidAccount");
    }

    return decryptedChallenges;
}

/**
 * @param {PrismConvertResponse[]} convertResponses 
 * @param {bigint[]} ids
 * @param {Point[]} mgORKi 
 * @param {bigint} r1 
 * @param {Uint8Array[]} prkECDHi
 */
export async function PrismConvertReply(convertResponses, ids, mgORKi, r1, prkECDHi){    
    // ∑ gPass ⋅ r1 ⋅ PRISMi ⋅ li / r1
    const gPassPRISM = Interpolation.AggregatePointsWithIds(convertResponses.map(resp => resp.GBlurPassPrismi), ids).divide(r1);
    const gPassPRISM_hashed = await gPassPRISM.hash();

    const prismAuthis = await DH.generateECDHi(mgORKi, gPassPRISM_hashed);

    let decPrismRequesti;
    try{
        const pre_decPrismRequesti = convertResponses.map(async (chall, i) => DecryptedPrismConvertResponse.from(await AES.decryptData(chall.EncRequesti, prismAuthis[i])));
        decPrismRequesti = await Promise.all(pre_decPrismRequesti);
    }catch{
        throw Error("enclave.invalidAccount");
    }
    const timestampi = median(decPrismRequesti.map(resp => resp.Timestampi));

    const pre_selfRequesti = decPrismRequesti.map(async (req, i) => await AES.decryptData(req.PRKRequesti, prkECDHi[i]));
    const selfRequesti = await Promise.all(pre_selfRequesti);

    // Calculate when the stored token expires
    const expired = CurrentTime() + Min(decPrismRequesti.map(d => d.Exti));

    return {prismAuthis, timestampi, selfRequesti, expired}
}
/**
 * @param {PrismConvertResponse[]} convertResponses 
 * @param {bigint[]} ids
 * @param {Point[]} mgORKi 
 * @param {bigint} r1 
 */
export async function DevicePrismConvertReply(convertResponses, ids, mgORKi, r1){    
    // ∑ gPass ⋅ r1 ⋅ PRISMi ⋅ li / r1
    const gPassPRISM = Interpolation.AggregatePointsWithIds(convertResponses.map(resp => resp.GBlurPassPrismi), ids).divide(r1);
    const gPassPRISM_hashed = await gPassPRISM.hash();

    const prismAuthis = await DH.generateECDHi(mgORKi, gPassPRISM_hashed);

    let decPrismRequesti;
    try{
        const pre_decPrismRequesti = convertResponses.map(async (chall, i) => DecryptedPrismConvertResponse.from(await AES.decryptData(chall.EncRequesti, prismAuthis[i])));
        decPrismRequesti = await Promise.all(pre_decPrismRequesti);
    }catch{
        throw Error("enclave.invalidAccount");
    }
    const timestampi = median(decPrismRequesti.map(resp => resp.Timestampi));

    // Calculate when the stored token expires
    const expired = CurrentTime() + Min(decPrismRequesti.map(d => d.Exti));

    return {prismAuthis, timestampi, prkRequesti: decPrismRequesti.map(d => d.PRKRequesti), expired}
}

/**
 * @param {CMKConvertResponse[]} convertResponses 
 * @param {bigint[]} ids
 * @param {Uint8Array[]} prismAuthis
 * @param {Point} gCMK 
 * @param {bigint} timestampi
 * @param {string} sessID
 * @param {string} purpose
 * @param {Point} qPub
 * @param {bigint} uDeObf
 * @param {bigint} blurerKPriv
 * @param {Ed25519PublicComponent} gSessKeyPub
 */
export async function CmkConvertReply(convertResponses, ids, prismAuthis, gCMK, timestampi, sessID, purpose, qPub, uDeObf, blurerKPriv, gSessKeyPub){
    let decData;
    try{
        const pre_decData = convertResponses.map(async (resp, i) => DecryptedCMKConvertResponse.from(await AES.decryptData(resp.EncChallengei, prismAuthis[i])));
        decData = await Promise.all(pre_decData);
    }catch{
        throw Error("enclave.invalidAccount");
    }

    const userPRISM = Interpolation.AggregatePointsWithIds(decData.map(d => d.UserPRISMi), ids);
    const userPRISMdec = userPRISM.mul(mod(BigIntFromByteArray(await DH.computeSharedKey(qPub, blurerKPriv))));

    const gUserCMK = userPRISMdec.divide(uDeObf);
    const gUserCMK_Hash = await Hash.SHA512_Digest(gUserCMK.toRawBytes());

    const CMKMul = mod(BigIntFromByteArray(gUserCMK_Hash.slice(0, 32)));
    const VUID = Bytes2Hex(gUserCMK_Hash.slice(-32));
    const gCMKAuth = gCMK.mul(CMKMul);
    const gCMKR = Interpolation.AggregatePoints(convertResponses.map(resp => resp.GCMKRi));
    const authToken = AuthRequest.new(VUID, purpose, gSessKeyPub.Serialize().ToString(), timestampi + randBetween(30, 90), sessID);
    const {blurHCMKMul, blur, gRMul} = await genBlindMessage(gCMKR, gCMKAuth, authToken.toUint8Array(), CMKMul);

    return {VUID: VUID, blurHCMKMul, r4: blur, gCMKAuth, authToken, gRMul}
}

/**
 * @param {Uint8Array[]} encRequesti
 * @param {Uint8Array[]} appAuthi
 * @param {bigint[]} ids
 * @param {Point} gCMK
 * @param {string} qPub
 * @param {string} uDeObf
 * @param {TideKey} blurerKPriv
 * @param {Ed25519PublicComponent} gSessKeyPub
 * @param {string} purpose
 * @param {string} sessionId
 * @param {Point} gCMKR
 */
export async function DeviceConvertReply(encRequesti, appAuthi, ids, gCMK, qPub, uDeObf, blurerKPriv, gSessKeyPub, purpose, sessionId, gCMKR){    
    let decPrismRequesti;
    try{
        const pre_decPrismRequesti = encRequesti.map(async (chall, i) => DecryptedDeviceConvertResponse.from(StringFromUint8Array(await AES.decryptDataRawOutput(chall, appAuthi[i]))));
        decPrismRequesti = await Promise.all(pre_decPrismRequesti);
    }catch(ex){
        console.log(ex);
        throw Error("enclave.invalidAccount");
    }
    const timestampi = median(decPrismRequesti.map(resp => resp.Timestampi));

    // Calculate when the stored token expires
    const expired = CurrentTime() + Min(decPrismRequesti.map(d => d.Exti));

    // CMK part
    const userPRISM = Interpolation.AggregatePointsWithIds(decPrismRequesti.map(d => d.UserPRISMi), ids);
    const userPRISMdec = userPRISM.mul(mod(BigIntFromByteArray(await DH.computeSharedKey(TideKey.FromSerializedComponent(qPub).get_public_component().public, blurerKPriv.get_private_component().priv))));

    const gUserCMK = userPRISMdec.divide(TideKey.FromSerializedComponent(uDeObf).get_private_component().priv);
    const gUserCMK_Hash = await Hash.SHA512_Digest(gUserCMK.toRawBytes());

    const CMKMul = mod(BigIntFromByteArray(gUserCMK_Hash.slice(0, 32)));
    const VUID = Bytes2Hex(gUserCMK_Hash.slice(-32));
    const gCMKAuth = gCMK.mul(CMKMul);
    const authToken = AuthRequest.new(VUID, purpose, gSessKeyPub.Serialize().ToString(), timestampi + randBetween(30, 90), sessionId);
    const {blurHCMKMul, blur, gRMul} = await genBlindMessage(gCMKR, gCMKAuth, authToken.toUint8Array(), CMKMul);

    return {VUID, gCMKAuth, authToken, r4: blur, decPrismRequesti, timestampi, expired, blurHCMKMul, gRMul}
}
/**
 * @param {ConvertRememberedResponse[]} responses 
 * @param {bigint[]} mIdORKi 
 * @param {Point} gCMK 
 * @param {string} sessID 
 * @param {Uint8Array[]} prkECDHi
 * @param {Point} qPub
 * @param {bigint} uDeObf
 * @param {bigint} blurerKPriv
 * @param {Ed25519PublicComponent} gSessKeyPub
 */
export async function ConvertRememberedReply(responses, mIdORKi, gCMK, sessID, prkECDHi, qPub, uDeObf, blurerKPriv, gSessKeyPub){
    const pre_decryptedResonses = responses.map((async(resp, i) => DecryptedConvertRememberedResponse.from(await AES.decryptData(resp.EncRequesti, prkECDHi[i]))));
    const decryptedResponses = await Promise.all(pre_decryptedResonses);

    const timestamp = Math.median(decryptedResponses.map(d => d.timestampi));

    const userPRISM = Interpolation.AggregatePointsWithIds(decryptedResponses.map(d => d.UserPRISMi), mIdORKi);
    const userPRISMdec = userPRISM.mul(mod(BigIntFromByteArray(await DH.computeSharedKey(qPub, blurerKPriv))));

    const gUserCMK = userPRISMdec.divide(uDeObf);
    const gUserCMK_Hash = await Hash.SHA512_Digest(gUserCMK.toRawBytes());

    const CMKMul = mod(BigIntFromByteArray(gUserCMK_Hash.slice(0, 32)));
    const VUID = Bytes2Hex(gUserCMK_Hash.slice(-32));
    const gCMKAuth = gCMK.mul(CMKMul);
    const gCMKR = Interpolation.AggregatePoints(responses.map(resp => resp.GCMKRi));

    const authToken = AuthRequest.new(VUID, "auth", gSessKeyPub.Serialize().ToString(), timestamp + randBetween(30, 90), sessID);

    const {blurHCMKMul, blur: r4, gRMul} = await genBlindMessage(gCMKR, gCMKAuth, authToken.toUint8Array(), CMKMul);
    return {
        VUID,
        gCMKAuth,
        blurHCMKMul,
        r4,
        gRMul,
        authToken,
        prkECDHi
    }
}
/**
 * 
 * @param {string} vuid 
 * @param {Uint8Array[]} prkECDHi
 * @param {string[]} encSigi 
 * @param {Point} gCMKAuth 
 * @param {AuthRequest} authToken 
 * @param {bigint} r4 
 * @param {Point} gRMul 
 * @param {Point} gVRK
 */
export async function AuthenticateBasicReply(vuid, prkECDHi, encSigi, gCMKAuth, authToken, r4, gRMul, gVRK){
    const pre_authResp = encSigi.map(async (enc, i) => AuthenticateResponse.from(await AES.decryptData(enc, prkECDHi[i])));
    const authResp = await Promise.all(pre_authResp);

    const blindS = mod(authResp.reduce((sum, next) => sum + next.Si, BigInt(0)));
    const sig = await unblindSignature(blindS, r4);
    const blindSigValid = await verifyBlindSignature(sig, gRMul, gCMKAuth, authToken.toUint8Array());
    if(!blindSigValid) throw Error("Blind Signature Failed");
    const blindSig = bytesToBase64(serializeBlindSig(sig, gRMul));

    if(gVRK == null){
        const vendorData = new VendorData(vuid, gCMKAuth, blindSig, authToken).toString();
        return vendorData;
    }else{
        const VendorEncryptedData = await ElGamal.encryptData(StringToUint8Array(new VendorData(vuid, gCMKAuth, blindSig, authToken).toString()), gVRK);
        return VendorEncryptedData;
    }
}
/**
 * 
 * @param {string} vuid 
 * @param {Uint8Array} sig 
 * @param {Point} gCMKAuth 
 * @param {AuthRequest} authToken 
 * @param {bigint} r4 
 * @param {Point} gRMul 
 * @param {Point} gVRK
 */
export async function AuthenticateDeviceReply(vuid, sig, gCMKAuth, authToken, r4, gRMul, gVRK){
    const blindS = BigIntFromByteArray(sig.slice(-32));
    const usig = await unblindSignature(blindS, r4);
    const blindSigValid = await verifyBlindSignature(usig, gRMul, gCMKAuth, authToken.toUint8Array());
    if(!blindSigValid) throw Error("Blind Signature Failed");
    const blindSig = bytesToBase64(serializeBlindSig(usig, gRMul));

    if(gVRK == null){
        const vendorData = new VendorData(vuid, gCMKAuth, blindSig, authToken).toString();
        return vendorData;
    }else{
        const VendorEncryptedData = await ElGamal.encryptData(StringToUint8Array(new VendorData(vuid, gCMKAuth, blindSig, authToken).toString()), gVRK);
        return VendorEncryptedData;
    }
}

/**
 * 
 * @param {string} vuid 
 * @param {Uint8Array[]} prkECDHi
 * @param {string[]} encSigi 
 * @param {Point} gCMKAuth 
 * @param {AuthRequest} authToken 
 * @param {bigint} r4 
 * @param {Point} gRMul 
 * @param {Point} gVRK
 * @param {bigint} sessKey
 * @param {string} consentToSign
 */
export async function AuthenticateConsentReply(vuid, prkECDHi, encSigi, gCMKAuth, authToken, r4, gRMul, gVRK, sessKey, consentToSign){
    const pre_authResp = encSigi.map(async (enc, i) => AuthenticateResponse.from(await AES.decryptData(enc, prkECDHi[i])));
    const authResp = await Promise.all(pre_authResp);

    const blindS = mod(authResp.reduce((sum, next) => sum + next.Si, BigInt(0)));
    const sig = await unblindSignature(blindS, r4);
    const blindSigValid = await verifyBlindSignature(sig, gRMul, gCMKAuth, authToken.toUint8Array());
    if(!blindSigValid) throw Error("Blind Signature Failed");
    const blindSig = bytesToBase64(serializeBlindSig(sig, gRMul));

    const vendorData = new VendorData(vuid, gCMKAuth, blindSig, authToken);
    const VendorEncryptedData = await ElGamal.encryptData(StringToUint8Array(JSON.stringify({
        VendorData: vendorData.toString(),
        Consent: (await EdDSA.sign(consentToSign, sessKey))
    })), gVRK);

    return VendorEncryptedData;
}