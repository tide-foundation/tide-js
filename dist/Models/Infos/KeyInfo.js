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
Object.defineProperty(exports, "__esModule", { value: true });
const Ed25519_1 = require("../../Cryptide/Ed25519");
const OrkInfo_1 = __importDefault(require("./OrkInfo"));
class KeyInfo {
    /**
     *
     * @param {string} userId
     * @param {Point} userPublic
     * @param {string} userM
     * @param {OrkInfo[]} orkInfo
     */
    constructor(userId, userPublic, userM, orkInfo) {
        this.UserId = userId;
        this.UserPublic = userPublic;
        this.UserM = userM;
        this.OrkInfo = orkInfo;
    }
    toString() {
        return JSON.stringify({
            UserId: this.UserId,
            UserPublic: this.UserPublic.toBase64(),
            UserM: this.UserM,
            OrkInfos: this.OrkInfo.map(info => info.toString())
        });
    }
    toNativeTypeObject() {
        return {
            UserId: this.UserId,
            UserPublic: this.UserPublic.toBase64(),
            UserM: this.UserM,
            OrkInfos: this.OrkInfo.map(info => info.toNativeTypeObject())
        };
    }
    static from(data) {
        const json = JSON.parse(data);
        const pub = Ed25519_1.Point.fromBase64(json.UserPublic);
        const orkInfo = json.OrkInfos.map(orkInfo => OrkInfo_1.default.from(orkInfo));
        return new KeyInfo(json.UserId, pub, json.UserM, orkInfo);
    }
    static fromNativeTypeObject(json) {
        return new KeyInfo(json.UserId, Ed25519_1.Point.fromBase64(json.UserPublic), json.UserM, json.OrkInfos.map(o => OrkInfo_1.default.fromNativeTypeObject(o)));
    }
}
exports.default = KeyInfo;
