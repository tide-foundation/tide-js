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

import { CreateTideMemory, writeInt64LittleEndian, WriteValue } from "./Serialization";
import { Utils } from "../index";
import { Ed25519PublicComponent } from "./Components/Schemes/Ed25519/Ed25519Components";
import { AuthorizerSignatureFormat } from "./Signing/TideSignature";

/**
 * 
 * @param {Ed25519PublicComponent} gvrk 
 * @param {number | bigint} expiry 
 */
export function CreateVRKPackage(gvrk, expiry){
    const serializedgvrk = gvrk.Serialize().ToBytes();
    const ex = typeof expiry == "bigint" ? expiry : BigInt(expiry);
    if(ex < BigInt(Utils.CurrentTime() + 5)) throw Error("Expiry must be at least 5 seconds into future");
    const time_b = writeInt64LittleEndian(ex);
    const vrk_pack = CreateTideMemory(serializedgvrk,
        4 + 4 + serializedgvrk.length + time_b.length
    );
    WriteValue(vrk_pack, 1, time_b);
    return vrk_pack;
}
/**
 * 
 * @param {string} authFlow 
 * @param {string[]} signModels 
 * @param {Uint8Array} vrk_pack 
 * @returns 
 */
export function CreateAuthorizerPackage(authFlow, signModels, vrk_pack){
    return new AuthorizerSignatureFormat(authFlow, signModels, vrk_pack).format();
}