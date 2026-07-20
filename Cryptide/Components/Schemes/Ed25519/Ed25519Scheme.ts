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

import { signNonDeterministicAsync, verifyAsync } from "../../../Ed25519";
import ElGamal from "../../../Encryption/ElGamal";
import BaseScheme from "../BaseScheme";
import { Ed25519PrivateComponent, Ed25519PublicComponent, Ed25519SeedComponent } from "./Ed25519Components";
import { TideError } from "../../../../Errors/TideError";
import { TideJsErrorCodes } from "../../../../Errors/codes";

export default class Ed25519Scheme extends BaseScheme{
    static get Name() { return "Ed25519Scheme"; }
    /**
     * WITHOUT DETERMINISM. Prefix is generated via randomisation.
     * @returns 
     */
    static GetSigningFunction = () => {
        const signingFunc = (msg, component) => {
            if(msg instanceof Uint8Array && component instanceof Ed25519PrivateComponent){
                return signNonDeterministicAsync(msg, component.priv);
            }
            throw new TideError({ code: TideJsErrorCodes.SERIAL_INVALID_TYPE, displayMessage: "Ed25519Scheme.sign: mismatch of expected types (Uint8Array, Ed25519PrivateComponent)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.ts:36" });
        }
        return signingFunc;
    }
    static GetVerifyingFunction = () => {
        const verifyingFunc = async (msg, signature, component) => {
            if(msg instanceof Uint8Array && signature instanceof Uint8Array && component instanceof Ed25519PublicComponent){
                const valid = await verifyAsync(signature, msg, component.rawBytes);
                if(!valid) throw new TideError({ code: TideJsErrorCodes.SIG_VERIFY_FAILED, displayMessage: "Ed25519 signature validation failed", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.ts:44" });
            }
            else throw new TideError({ code: TideJsErrorCodes.SERIAL_INVALID_TYPE, displayMessage: "Ed25519Scheme.verify: mismatch of expected types (Uint8Array, Uint8Array, Ed25519PublicComponent)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.ts:46" });
        }
        return verifyingFunc;
    }
    static GetEncryptingFunction = () => {
        const encryptingFunc = async (msg, component) => {
            if(msg instanceof Uint8Array && component instanceof Ed25519PublicComponent){
                return await ElGamal.encryptDataRaw(msg, component.public);
            }
            else throw new TideError({ code: TideJsErrorCodes.SERIAL_INVALID_TYPE, displayMessage: "Ed25519Scheme.encrypt: mismatch between expected types (Uint8Array, Ed25519PublicComponent)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.ts:55" });
        }
        return encryptingFunc;
    }
    static GetDecryptingFunction = () => {
        const decryptingFunc = async (cipher, component) => {
            if(cipher instanceof Uint8Array && component instanceof Ed25519PrivateComponent){
                return await ElGamal.decryptDataRaw(cipher, component.priv);
            }
            else throw new TideError({ code: TideJsErrorCodes.SERIAL_INVALID_TYPE, displayMessage: "Ed25519Scheme.decrypt: mismatch between expected types (Uint8Array, Ed25519PrivateComponent)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.ts:64" });
        }
        return decryptingFunc;
    }
}