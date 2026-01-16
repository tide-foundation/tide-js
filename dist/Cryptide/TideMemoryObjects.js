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
Object.defineProperty(exports, "__esModule", { value: true });
exports.CreateVRKPackage = CreateVRKPackage;
exports.CreateAuthorizerPackage = CreateAuthorizerPackage;
const Serialization_1 = require("./Serialization");
const index_1 = require("../index");
const TideSignature_1 = require("./Signing/TideSignature");
/**
 *
 * @param {Ed25519PublicComponent} gvrk
 * @param {number | bigint} expiry
 */
function CreateVRKPackage(gvrk, expiry) {
    const serializedgvrk = gvrk.Serialize().ToBytes();
    const ex = typeof expiry == "bigint" ? expiry : BigInt(expiry);
    if (ex < BigInt(index_1.Utils.CurrentTime() + 5))
        throw Error("Expiry must be at least 5 seconds into future");
    const time_b = (0, Serialization_1.writeInt64LittleEndian)(ex);
    const vrk_pack = (0, Serialization_1.CreateTideMemory)(serializedgvrk, 4 + 4 + serializedgvrk.length + time_b.length);
    (0, Serialization_1.WriteValue)(vrk_pack, 1, time_b);
    return vrk_pack;
}
/**
 *
 * @param {string} authFlow
 * @param {string[]} signModels
 * @param {Uint8Array} vrk_pack
 * @returns
 */
function CreateAuthorizerPackage(authFlow, signModels, vrk_pack) {
    return new TideSignature_1.AuthorizerSignatureFormat(authFlow, signModels, vrk_pack).format();
}
