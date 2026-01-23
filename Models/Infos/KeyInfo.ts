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
import OrkInfo from "./OrkInfo";

export default class KeyInfo{
    UserId: any;
    UserPublic: any;
    UserM: any;
    OrkInfo: any;

    /**
     *
     * @param {string} userId
     * @param {Point} userPublic
     * @param {string} userM
     * @param {OrkInfo[]} orkInfo
     */
    constructor(userId, userPublic, userM, orkInfo){
        this.UserId = userId
        this.UserPublic = userPublic
        this.UserM = userM;
        this.OrkInfo = orkInfo
    }

    toString(){
        return JSON.stringify({
            UserId: this.UserId,
            UserPublic: this.UserPublic.toBase64(),
            UserM: this.UserM,
            OrkInfos: this.OrkInfo.map(info => info.toString())
        })
    }

    toNativeTypeObject(){
        return {
            UserId: this.UserId,
            UserPublic: this.UserPublic.toBase64(),
            UserM: this.UserM,
            OrkInfos: this.OrkInfo.map(info => info.toNativeTypeObject())
        }
    }

    static from(data){
        const json = JSON.parse(data);
        const pub = Point.fromBase64(json.UserPublic);
        const orkInfo = json.OrkInfos.map(orkInfo => OrkInfo.from(orkInfo));
        return new KeyInfo(json.UserId, pub, json.UserM, orkInfo);
    }

    static fromNativeTypeObject(json){
        return new KeyInfo(json.UserId, Point.fromBase64(json.UserPublic), json.UserM, json.OrkInfos.map(o => OrkInfo.fromNativeTypeObject(o)));
    }
}