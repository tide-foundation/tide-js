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

import { signNonDeterministicAsync, verifyAsync } from "../../../Ed25519.js";
import ElGamal from "../../../Encryption/ElGamal.js";
import BaseScheme from "../BaseScheme.js";
import { Ed25519PrivateComponent, Ed25519PublicComponent, Ed25519SeedComponent } from "./Ed25519Components.js";

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
            throw Error("Mismatch of expected types (Uint8Array, Ed25519PrivateComponent)");
        }
        return signingFunc;
    }
    static GetVerifyingFunction = () => {
        const verifyingFunc = async (msg, signature, component) => {
            if(msg instanceof Uint8Array && signature instanceof Uint8Array && component instanceof Ed25519PublicComponent){
                const valid = await verifyAsync(signature, msg, component.rawBytes);
                if(!valid) throw Error("Signature validation failed");
            }
            else throw Error("Mismatch of expected types (Uint8Array, Uint8Array, Ed25519PublicComponent)");
        }
        return verifyingFunc;
    }
    static GetEncryptingFunction = () => {
        const encryptingFunc = async (msg, component) => {
            if(msg instanceof Uint8Array && component instanceof Ed25519PublicComponent){
                return await ElGamal.encryptDataRaw(msg, component.public);
            }
            else throw Error("Mismatch between expected types (Uint8Array, Ed25519PublicComponent)");
        }
        return encryptingFunc;
    }
    static GetDecryptingFunction = () => {
        const decryptingFunc = async (cipher, component) => {
            if(cipher instanceof Uint8Array && component instanceof Ed25519PrivateComponent){
                return await ElGamal.decryptDataRaw(cipher, component.priv);
            }
            else throw Error("Mismatch between expected types (Uint8Array, Ed25519PrivateComponent)");
        }
        return decryptingFunc;
    }
}