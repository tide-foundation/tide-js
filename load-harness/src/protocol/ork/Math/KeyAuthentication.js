// Copied from ork/Ork/Ork/Enclave/js/Math/KeyAuthentication.js at git 12e9f082 for tide-js load-harness v2.
// Patches:
//   1. timeSkew shim: 4 `window.localStorage.setItem("timeSkew", ...)` sites
//      (original lines ~117, ~158, ~247, ~284) replaced with comments and a
//      `Math.floor` fallback (no `window.Math`) — per-VU is single-shot so
//      retaining timeSkew across iterations is unnecessary in Node.
//   2. Off-path imports/functions removed: DevicePrismConvertReply,
//      DeviceConvertReply, ConvertRememberedReply, GetDecryptedChallenge,
//      AuthenticateDeviceReply are gutted (replaced by throw stubs). They
//      reference Models we did NOT copy
//      (DecryptedConvertRememberedResponse, DecryptedDeviceConvertResponse,
//      ConvertRememberedResponse, DeviceConvertResponse) and are not
//      reachable from the cmkOnly password-login path.
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


import { Cryptide, Tools, Models, Errors } from "@tideorg/js";

const { HMAC_forHashing, SHA256_Digest, SHA512_Digest } = Cryptide.Hashing.Hash;
const { CurrentTime, randBetween } = Tools;
const { ConcatUint8Arrays, Bytes2Hex, bytesToBase64, BigIntFromByteArray, StringToUint8Array, StringFromUint8Array } = Cryptide.Serialization;
const { Min, median, mod, mod_inv } = Cryptide.Math;
const AES = Cryptide.Encryption.AES;
const DH = Cryptide.Encryption.DH;
const EdDSA = Cryptide.Signing.EdDSA;
const ElGamal = Cryptide.Encryption.ElGamal;
const Interpolation = Cryptide.Interpolation;
const Hash = Cryptide.Hashing.Hash;
const MathNS = Cryptide.Math;
const { genBlindMessage, serializeBlindSig, unblindSignature, verifyBlindSignature } = Cryptide.Signing.BlindSig;
const { Point } = Cryptide.Ed25519;
const Ed25519PublicComponent = Cryptide.Components.Schemes.Ed25519.Ed25519PublicComponent;
const TideKey = Cryptide.TideKey;
const { BaseComponent } = Cryptide.Components;
const AuthRequest = Models.AuthRequest;
const VendorData = Models.VendorData;

import PrismConvertResponse from "../Models/KeyAuth/Convert/PrismConvertResponse.js";
import DecryptedCMKConvertResponse from "../Models/KeyAuth/Convert/DecryptedCMKConvertResponse.js";
import CMKConvertResponse from "../Models/KeyAuth/Convert/CMKConvertResponse.js";
import DecryptedPrismConvertResponse from "../Models/KeyAuth/Convert/DecryptedPrismConvertResponse.js";
import AuthenticateResponse from "../Models/KeyAuth/Authenticate/AuthenticateResponse.js";
// Off-path imports removed (Device / Remembered models not copied; functions
// using them are stubbed below):
//   DecryptedConvertRememberedResponse, ConvertRememberedResponse,
//   DeviceConvertResponse, DecryptedDeviceConvertResponse.

/**
 * For use in change password flow.
 * STUB: change-password is not on the cmkOnly password-login load path; the
 * decrypted-challenges output is consumed only by that flow.
 */
export async function GetDecryptedChallenge(){
    throw new Error("GetDecryptedChallenge not ported to tide-js load-harness (off-path: change-password flow only)");
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
    }catch(ex){
        throw new Errors.TideError({
            code: Errors.TideJsErrorCodes.VAL_INVALID_ACCOUNT,
            displayMessage: "enclave.invalidAccount",
            messageKey: "enclave.invalidAccount",
            source: "tide-js/load-harness/src/protocol/ork/Math/KeyAuthentication.js (PrismConvertReply)",
            details: [{
                endpoint: "PrismConvertReply",
                displayMessage: `AES.decryptData of EncRequesti failed across ${convertResponses?.length ?? "<missing>"} ORK responses (likely wrong PRISM-derived key -> wrong password). Used in password sign-in convert step.`,
            }],
            cause: ex,
        });
    }
    const timestampi = median(decPrismRequesti.map(resp => resp.Timestampi));
    // timeSkew not retained in Node load-harness — per-VU is single-shot.
    // (Original: window.localStorage.setItem("timeSkew", String(timestampi - BigInt(window.Math.floor(Date.now() / 1000)))))

    const pre_selfRequesti = decPrismRequesti.map(async (req, i) => await AES.decryptData(req.PRKRequesti, prkECDHi[i]));
    const selfRequesti = await Promise.all(pre_selfRequesti);

    // Calculate when the stored token expires
    const expired = CurrentTime() + Min(decPrismRequesti.map(d => d.Exti));

    return {prismAuthis, timestampi, selfRequesti, expired}
}

/**
 * STUB: device convert path is not on the cmkOnly password-login load path.
 */
export async function DevicePrismConvertReply(){
    throw new Error("DevicePrismConvertReply not ported to tide-js load-harness (off-path: device convert flow only)");
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
 * @param {string|undefined} dPoPApproval
 */
export async function CmkConvertReply(convertResponses, ids, prismAuthis, gCMK, timestampi, sessID, purpose, qPub, uDeObf, blurerKPriv, gSessKeyPub, dPoPApproval){
    let decData;
    try{
        const pre_decData = convertResponses.map(async (resp, i) => DecryptedCMKConvertResponse.from(await AES.decryptData(resp.EncChallengei, prismAuthis[i])));
        decData = await Promise.all(pre_decData);
    }catch(ex){
        throw new Errors.TideError({
            code: Errors.TideJsErrorCodes.VAL_INVALID_ACCOUNT,
            displayMessage: "enclave.invalidAccount",
            messageKey: "enclave.invalidAccount",
            source: "tide-js/load-harness/src/protocol/ork/Math/KeyAuthentication.js (CmkConvertReply)",
            details: [{
                endpoint: "CmkConvertReply",
                displayMessage: `AES.decryptData of EncChallengei failed across ${convertResponses?.length ?? "<missing>"} ORK responses (likely wrong PRISM-derived key -> wrong password). purpose=${purpose ?? "<missing>"} sessID=${sessID ? sessID.slice(0, 16) + "..." : "<missing>"}`,
            }],
            cause: ex,
        });
    }

    const userPRISM = Interpolation.AggregatePointsWithIds(decData.map(d => d.UserPRISMi), ids);
    const userPRISMdec = userPRISM.mul(mod(BigIntFromByteArray(await DH.computeSharedKey(qPub, blurerKPriv))));

    const gUserCMK = userPRISMdec.divide(uDeObf);
    const gUserCMK_Hash = await Hash.SHA512_Digest(gUserCMK.toRawBytes());

    const CMKMul = mod(BigIntFromByteArray(gUserCMK_Hash.slice(0, 32)));
    const VUID = Bytes2Hex(gUserCMK_Hash.slice(-32));
    const gCMKAuth = gCMK.mul(CMKMul);
    const gCMKR = Interpolation.AggregatePoints(convertResponses.map(resp => resp.GCMKRi));
    const authToken = AuthRequest.new(VUID, purpose, gSessKeyPub.Serialize().ToString(), timestampi + randBetween(30, 90), sessID, dPoPApproval);
    const {blurHCMKMul, blur, gRMul} = await genBlindMessage(gCMKR, gCMKAuth, authToken.toUint8Array(), CMKMul);

    return {VUID: VUID, blurHCMKMul, r4: blur, gCMKAuth, authToken, gRMul}
}

/**
 * STUB: device convert path is not on the cmkOnly password-login load path.
 */
export async function DeviceConvertReply(){
    throw new Error("DeviceConvertReply not ported to tide-js load-harness (off-path: device convert flow only)");
}

/**
 * STUB: passwordless (remembered-device) flow is not on the cmkOnly
 * password-login load path.
 */
export async function ConvertRememberedReply(){
    throw new Error("ConvertRememberedReply not ported to tide-js load-harness (off-path: remembered-device flow only)");
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
    if(!blindSigValid) throw new Errors.TideError({
        code: Errors.TideJsErrorCodes.SIG_BLIND_VERIFY_FAILED,
        displayMessage: "We couldn't complete sign-in because a security check (signature verification) didn't pass. Please try signing in again. If the problem persists, contact support.",
        source: "tide-js/load-harness/src/protocol/ork/Math/KeyAuthentication.js (AuthenticateBasicReply)",
        details: [{
            endpoint: "AuthenticateBasicReply",
            displayMessage: `Blind signature verification failed during basic (password) authentication. vuid=${vuid ? vuid.slice(0, 16) + "..." : "<missing>"} purpose=${authToken?.purpose ?? "<missing>"} sessionId=${authToken?.sessionId ? authToken.sessionId.slice(0, 16) + "..." : "<missing>"} orkResponseCount=${encSigi?.length ?? "<missing>"}`,
        }],
    });
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
 * STUB: device-authenticate (passwordless) is not on the cmkOnly
 * password-login load path.
 */
export async function AuthenticateDeviceReply(){
    throw new Error("AuthenticateDeviceReply not ported to tide-js load-harness (off-path: device/passwordless flow only)");
}
