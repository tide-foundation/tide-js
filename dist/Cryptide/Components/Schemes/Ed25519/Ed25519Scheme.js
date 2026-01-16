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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
const Ed25519_1 = require("../../../Ed25519");
const ElGamal_1 = __importDefault(require("../../../Encryption/ElGamal"));
const BaseScheme_1 = __importDefault(require("../BaseScheme"));
const Ed25519Components_1 = require("./Ed25519Components");
class Ed25519Scheme extends BaseScheme_1.default {
    static get Name() { return "Ed25519Scheme"; }
}
_a = Ed25519Scheme;
/**
 * WITHOUT DETERMINISM. Prefix is generated via randomisation.
 * @returns
 */
Ed25519Scheme.GetSigningFunction = () => {
    const signingFunc = (msg, component) => {
        if (msg instanceof Uint8Array && component instanceof Ed25519Components_1.Ed25519PrivateComponent) {
            return (0, Ed25519_1.signNonDeterministicAsync)(msg, component.priv);
        }
        throw Error("Mismatch of expected types (Uint8Array, Ed25519PrivateComponent)");
    };
    return signingFunc;
};
Ed25519Scheme.GetVerifyingFunction = () => {
    const verifyingFunc = async (msg, signature, component) => {
        if (msg instanceof Uint8Array && signature instanceof Uint8Array && component instanceof Ed25519Components_1.Ed25519PublicComponent) {
            const valid = await (0, Ed25519_1.verifyAsync)(signature, msg, component.rawBytes);
            if (!valid)
                throw Error("Signature validation failed");
        }
        else
            throw Error("Mismatch of expected types (Uint8Array, Uint8Array, Ed25519PublicComponent)");
    };
    return verifyingFunc;
};
Ed25519Scheme.GetEncryptingFunction = () => {
    const encryptingFunc = async (msg, component) => {
        if (msg instanceof Uint8Array && component instanceof Ed25519Components_1.Ed25519PublicComponent) {
            return await ElGamal_1.default.encryptDataRaw(msg, component.public);
        }
        else
            throw Error("Mismatch between expected types (Uint8Array, Ed25519PublicComponent)");
    };
    return encryptingFunc;
};
Ed25519Scheme.GetDecryptingFunction = () => {
    const decryptingFunc = async (cipher, component) => {
        if (cipher instanceof Uint8Array && component instanceof Ed25519Components_1.Ed25519PrivateComponent) {
            return await ElGamal_1.default.decryptDataRaw(cipher, component.priv);
        }
        else
            throw Error("Mismatch between expected types (Uint8Array, Ed25519PrivateComponent)");
    };
    return decryptingFunc;
};
exports.default = Ed25519Scheme;
