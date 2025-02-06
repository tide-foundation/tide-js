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
import { ConcatUint8Arrays, Bytes2Hex, bytesToBase64, BigIntFromByteArray, StringToUint8Array } from "../Cryptide/Serialization.js";
import { Min, median, mod, mod_inv } from "../Cryptide/Math.js";
import PrismConvertResponse from "../Models/Responses/KeyAuth/Convert/PrismConvertResponse.js";
import { AES, DH, EdDSA, ElGamal, Hash, Interpolation, Math, Point } from "../Cryptide/index.js";
import DecryptedCMKConvertResponse from "../Models/Responses/KeyAuth/Convert/DecryptedCMKConvertResponse.js";
import CMKConvertResponse from "../Models/Responses/KeyAuth/Convert/CMKConvertResponse.js";
import DecryptedPrismConvertResponse from "../Models/Responses/KeyAuth/Convert/DecryptedPrismConvertResponse.js";
import AuthRequest from "../Models/AuthRequest.js";
import { genBlindMessage, serializeBlindSig, unblindSignature, verifyBlindSignature } from "../Cryptide/Signing/BlindSig.js";
import AuthenticateResponse from "../Models/Responses/KeyAuth/Authenticate/AuthenticateResponse.js";
import DecryptedConvertRememberedResponse from "../Models/Responses/KeyAuth/Convert/DecryptedConvertRememberedResponse.js";
import ConvertRememberedResponse from "../Models/Responses/KeyAuth/Convert/ConvertRememberedResponse.js";
import VendorData from "../Models/VendorData.js";
/**
 * For use in change password flow
 * @param {PrismConvertResponse[]} convertResponses 
 * @param {bigint[]} lis 
 * @param {Point[]} mgORKi 
 * @param {bigint} r1 
 * @returns 
 */
export async function GetDecryptedChallenge(convertResponses, lis, mgORKi, r1){
    const gPassPRISM = convertResponses.reduce((sum, next, i) => sum.add(next.GBlurPassPrismi.times(lis[i])), Point.infinity).times(mod_inv(r1));
    const gPassPRISM_hashed = mod(BigIntFromByteArray(await SHA256_Digest(gPassPRISM.toArray())));

    const pre_prismAuthi = mgORKi.map(async ork => await SHA256_Digest(ork.times(gPassPRISM_hashed).toArray())) // create a prismAuthi for each ork
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
    const gPassPRISM = Interpolation.AggregatePointsWithIds(convertResponses.map(resp => resp.GBlurPassPrismi), ids).unblur(r1);
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
 */
export async function CmkConvertReply(convertResponses, ids, prismAuthis, gCMK, timestampi, sessID, purpose, qPub, uDeObf, blurerKPriv){
    let decData;
    try{
        const pre_decData = convertResponses.map(async (resp, i) => DecryptedCMKConvertResponse.from(await AES.decryptData(resp.EncChallengei, prismAuthis[i])));
        decData = await Promise.all(pre_decData);
    }catch{
        throw Error("enclave.invalidAccount");
    }

    const userPRISM = Interpolation.AggregatePointsWithIds(decData.map(d => d.UserPRISMi), ids);
    const userPRISMdec = userPRISM.times(BigIntFromByteArray(await DH.computeSharedKey(qPub, blurerKPriv)));

    const gUserCMK = userPRISMdec.unblur(uDeObf);
    const gUserCMK_Hash = await Hash.SHA512_Digest(gUserCMK.toArray());

    const CMKMul = mod(BigIntFromByteArray(gUserCMK_Hash.slice(0, 32)));
    const VUID = Bytes2Hex(gUserCMK_Hash.slice(-32));
    const gCMKAuth = gCMK.times(CMKMul);
    const gCMKR = Interpolation.AggregatePoints(convertResponses.map(resp => resp.GCMKRi));
    const authToken = AuthRequest.new(VUID, purpose, sessID, timestampi + randBetween(30, 90));

    const {blurHCMKMul, blur, gRMul} = await genBlindMessage(gCMKR, gCMKAuth, authToken.toUint8Array(), CMKMul);

    return {VUID: VUID, blurHCMKMul, r4: blur, gCMKAuth, authToken, gRMul}
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
 */
export async function ConvertRememberedReply(responses, mIdORKi, gCMK, sessID, prkECDHi, qPub, uDeObf, blurerKPriv){
    const pre_decryptedResonses = responses.map((async(resp, i) => DecryptedConvertRememberedResponse.from(await AES.decryptData(resp.EncRequesti, prkECDHi[i]))));
    const decryptedResponses = await Promise.all(pre_decryptedResonses);

    const timestamp = Math.median(decryptedResponses.map(d => d.Timestampi));

    const userPRISM = Interpolation.AggregatePointsWithIds(decryptedResponses.map(d => d.UserPRISMi), mIdORKi);
    const userPRISMdec = userPRISM.times(BigIntFromByteArray(await DH.computeSharedKey(qPub, blurerKPriv)));

    const gUserCMK = userPRISMdec.unblur(uDeObf);
    const gUserCMK_Hash = await Hash.SHA512_Digest(gUserCMK.toArray());

    const CMKMul = mod(BigIntFromByteArray(gUserCMK_Hash.slice(0, 32)));
    const VUID = Bytes2Hex(gUserCMK_Hash.slice(-32));
    const gCMKAuth = gCMK.times(CMKMul);
    const gCMKR = Interpolation.AggregatePoints(responses.map(resp => resp.GCMKRi));

    const authToken = AuthRequest.new(VUID, "auth", sessID, timestamp + randBetween(30, 90));

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

    const VendorEncryptedData = await ElGamal.encryptData(StringToUint8Array(new VendorData(vuid, gCMKAuth, blindSig, authToken).toString()), gVRK);
    return VendorEncryptedData;
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

/**
 * @param {string[]} encSig
 * @param {string[]} encGRData 
 * @param {object} data_for_PreSignInCVK 
 * @param {Point[]} vgORKi
 */
export async function PreSignInCVKReply(encSig, encGRData, data_for_PreSignInCVK, vgORKi){
    throw Error("Depracted")
    const pre_authResp = encSig.map(async (enc, i) => AuthenticateResponse.from(await AES.decryptData(enc, data_for_PreSignInCVK.prismAuthis[i])));
    const authResp = await Promise.all(pre_authResp);

    const mod_inv_r4 = mod_inv(data_for_PreSignInCVK.r4);
    const S = mod(authResp.reduce((sum, next) => sum + next.Si, BigInt(0)) * mod_inv_r4);
    const gBlindH = authResp.reduce((sum, next) => sum.add(next.GBlindHi), Point.infinity).times(mod_inv_r4);

    const _8 = BigInt(8);
    const hash_CMKAuth = mod(BigIntFromByteArray(await SHA256_Digest("CMK authentication")));
    if(!(Point.g.times(S).times(_8).isEqual(data_for_PreSignInCVK.gRMul.times(_8).add(data_for_PreSignInCVK.gCMKAuth.times(data_for_PreSignInCVK.H).times(_8)).add(gBlindH.times(hash_CMKAuth).times(_8))))){
        throw new Error("Blind signature failed");
    }

    const pre_ECDHi = vgORKi.map(async pub => await SHA256_Digest(pub.times(data_for_PreSignInCVK.SessKey).toArray()));
    const ECDHi = await Promise.all(pre_ECDHi);

    const pre_gRs = encGRData.map(async (enc, i) => PreSignInResponse.from(await AES.decryptData(enc, ECDHi[i])));
    const gRs = await Promise.all(pre_gRs);

    // check theres the same amount of gRis in each response
    if(!gRs.every(gr => gr.GRi.length == gRs[0].GRi.length)) throw Error('One ORK returned incorrect number of gRs');
    const gCVKRi = gRs[0].GRi.map((_, i) => gRs.reduce((sum, next) => sum.add(next.GRi[i]), Point.infinity));
    return {gCVKRi: gCVKRi, S: S, ECDHi: ECDHi, gBlindH: gBlindH}
}

/**
 * 
 * @param {string[]} encSigs 
 * @param {Point[]} gRis
 * @param {Uint8Array[]} ECDHi 
 * @param {bigint[]} vLis
 * @param {bool} tokenRequested
 * @param {object} model
 */
export async function SignInCVKReply(encSigs, gRis, ECDHi, vLis, tokenRequested, model=null){
    throw Error("Deprecated")
    const pre_Sigs = encSigs.map(async (enc, i) => SignInResponse.from(await AES.decryptData(enc, ECDHi[i])));
    const Sigs = await Promise.all(pre_Sigs);

    let CVKS;
    let modelSig;
    let counter = 0;
    if(tokenRequested){
        CVKS = mod(Sigs.reduce((sum, next, i) => sum + (next.Si[counter] * vLis[i]), BigInt(0)));
        counter++;
    }
    if(model != null){
        const modelS = mod(Sigs.reduce((sum, next, i) => sum + (next.Si[counter] * vLis[i]), BigInt(0)));
        modelSig = bytesToBase64(ConcatUint8Arrays([gRis[counter].toArray(), BigIntToByteArray(modelS)])); // get first gRi
        counter++;
    }
    return {CVKS: CVKS, modelSig: modelSig};
}