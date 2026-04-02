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

import { Point } from "../../Cryptide/Ed25519";
import { base64ToBytes, bytesToBase64 } from "../../Cryptide/Serialization";
import OrkInfo from "./OrkInfo";

export default class KeyInfo{
    UserId: string;
    UserPublic: Point;
    UserM: string;
    OrkInfo: OrkInfo[];
    CommitR: Point;
    CommitS: bigint;
    OrksBitwise: Uint8Array;

    constructor(userId: string, userPublic: Point, userM: string, orkInfo: OrkInfo[], commitR: Point, commitS: bigint, orksBitwise: Uint8Array){
        this.UserId = userId
        this.UserPublic = userPublic
        this.UserM = userM;
        this.OrkInfo = orkInfo
        this.CommitR = commitR
        this.CommitS = commitS
        this.OrksBitwise = orksBitwise
    }

    toString(){
        return JSON.stringify({
            UserId: this.UserId,
            UserPublic: this.UserPublic.toBase64(),
            UserM: this.UserM,
            OrkInfos: this.OrkInfo.map(info => info.toString()),
            UserGR: this.CommitR.toBase64(),
            UserS: this.CommitS.toString(),
            UserOrksBitwise: bytesToBase64(this.OrksBitwise)
        })
    }

    toNativeTypeObject(){
        return {
            UserId: this.UserId,
            UserPublic: this.UserPublic.toBase64(),
            UserM: this.UserM,
            OrkInfos: this.OrkInfo.map(info => info.toNativeTypeObject()),
            UserGR: this.CommitR.toBase64(),
            UserS: this.CommitS.toString(),
            UserOrksBitwise: bytesToBase64(this.OrksBitwise)
        }
    }

    static from(data: string){
        const json = JSON.parse(data);
        const pub = Point.fromBase64(json.UserPublic);
        const orkInfo = json.OrkInfos.map(orkInfo => OrkInfo.from(orkInfo));
        const commitR = Point.fromBase64(json.UserGR);
        const commitS = BigInt(json.UserS);
        const orksBitwise = base64ToBytes(json.UserOrksBitwise);
        return new KeyInfo(json.UserId, pub, json.UserM, orkInfo, commitR, commitS, orksBitwise);
    }

    static fromNativeTypeObject(json: any){
        return new KeyInfo(
            json.UserId,
            Point.fromBase64(json.UserPublic),
            json.UserM,
            json.OrkInfos.map(o => OrkInfo.fromNativeTypeObject(o)),
            Point.fromBase64(json.UserGR),
            BigInt(json.UserS),
            base64ToBytes(json.UserOrksBitwise)
        );
    }
}