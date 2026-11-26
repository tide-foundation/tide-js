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

import { RandomBigInt, mod, mod_inv } from "../Math";
import { Point } from "../Ed25519";
import { SHA512_Digest } from "../Hashing/Hash";
import { BigIntFromByteArray, BigIntToByteArray, ConcatUint8Arrays, bytesToBase64 } from "../Serialization";
import * as EdDSA from "./EdDSA";
import { TideError } from "../../Errors/TideError";
import { TideJsErrorCodes } from "../../Errors/codes";
export async function genBlindMessage(gR: Point, pub: Point, message: Uint8Array, multiplier: bigint){
    const blur = RandomBigInt();
    const gRMul = gR.mul(mod_inv(blur));
    const eddsaH = mod(BigIntFromByteArray(await SHA512_Digest(ConcatUint8Arrays([gRMul.toRawBytes(), pub.toRawBytes(), message]))));
    const blurHCMKMul = mod(eddsaH * multiplier * blur);

    return {blurHCMKMul, blur, gRMul};
}
export async function unblindSignature(blindS: bigint, blur: bigint){
    const s = mod(blindS * mod_inv(blur));
    return s;
}

/**
 * Verify a blind EdDSA signature against the supplied nonce/public key/message.
 *
 * Returns `true`/`false` so existing call-sites (notably the ork enclave's
 * `KeyAuthentication.AuthenticateBasicReply` / `AuthenticateDeviceReply`)
 * continue to work unchanged. On failure, however, this function now emits a
 * structured {@link TideError} via `console.error` so a developer inspecting
 * the browser console gets the same multi-line detail block (code, source,
 * inputs that failed) the rest of tide-js produces on uncaught throws —
 * instead of a single opaque `Signature failed.` line.
 *
 * Callers that need to throw on verification failure should construct their
 * own {@link TideError} with `code: TideJsErrorCodes.SIG_BLIND_VERIFY_FAILED`,
 * a user-friendly `displayMessage`, and any local context (e.g. orkUrl, vuid)
 * in `details` — see the blocked enclave-side TODO documented in this commit.
 */
export async function verifyBlindSignature(S: bigint, noncePublic: Point, pub: Point, message: Uint8Array){
    const valid = await EdDSA.verifyRaw(S, noncePublic, pub, message);

    if(!valid){
        // Build a TideError purely for its toString() — we don't throw it here
        // because the boolean return shape is a cross-package contract. The
        // structured form ensures `code`, `source` and the failing-input
        // fingerprints all surface as one log entry in the dev console.
        const diagnostic = new TideError({
            code: TideJsErrorCodes.SIG_BLIND_VERIFY_FAILED,
            displayMessage: "Local blind-signature verification failed against the expected challenge.",
            source: "Cryptide/Signing/BlindSig.ts:verifyBlindSignature",
            details: [
                {
                    displayMessage: "verifyRaw returned false",
                    // Per-field fingerprints kept short so the console line is
                    // skimmable; full base64 follows on its own keys for copy-paste.
                    code: `M=${bytesToBase64(message).slice(0, 16)}... S=${S.toString().slice(0, 12)}... nonce=${noncePublic.toBase64().slice(0, 12)}... pub=${pub.toBase64().slice(0, 12)}...`,
                },
            ],
        });
        // Attach the full inputs as an extra structured property so devs can
        // expand the logged object and grab them verbatim — the inline
        // `details[].code` field above is only a fingerprint preview.
        (diagnostic as any).inputs = {
            messageBase64: bytesToBase64(message),
            S: S.toString(),
            noncePublicBase64: noncePublic.toBase64(),
            publicBase64: pub.toBase64(),
        };
        console.error(diagnostic.toString(), diagnostic);
    }
    return valid;
}

export function serializeBlindSig(S: bigint, noncePublic: Point){
    return ConcatUint8Arrays([BigIntToByteArray(S), noncePublic.toRawBytes()]);
}