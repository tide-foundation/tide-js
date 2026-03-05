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

import { base64ToBytes, bytesToBase64 } from "../Cryptide/Serialization";
import KeyInfo from "./Infos/KeyInfo";
export default class EnclaveEntry{
    username: string;
    persona: string;
    expired: bigint;
    userInfo: KeyInfo;
    orksBitwise: (0 | 1)[];
    selfRequesti: string[];
    sessKey: Uint8Array;

    constructor(username: string, persona: string, expired: bigint, userInfo: KeyInfo, orksBitwise: (0 | 1)[], selfRequesti: string[], sessKey: Uint8Array){
        this.username = username;
        this.persona = persona;
        this.expired = expired;
        this.userInfo = userInfo;
        this.orksBitwise = orksBitwise;
        this.selfRequesti = selfRequesti;
        this.sessKey = sessKey;
    }
    toString(){
        return JSON.stringify({
            username: this.username,
            persona: this.persona,
            expired: this.expired.toString(),
            userInfo: this.userInfo.toNativeTypeObject(),
            orksBitwise: JSON.stringify(this.orksBitwise),
            selfRequesti: this.selfRequesti,
            sessKey: bytesToBase64(this.sessKey)
        });
    }
    static from(data: string){
        const json = JSON.parse(data);
        const expired = BigInt(json.expired);
        const userInfo = KeyInfo.fromNativeTypeObject(json.userInfo); // includes uid + gCMK, ork URL + id + pubs 
        const orksBitwise = JSON.parse(json.orksBitwise);
        const selfRequesti = json.selfRequesti;
        const sessKey = base64ToBytes(json.sessKey);
        return new EnclaveEntry(json.username, json.persona, expired, userInfo, orksBitwise, selfRequesti, sessKey);
    }
}