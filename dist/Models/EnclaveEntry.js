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
const Serialization_1 = require("../Cryptide/Serialization");
const KeyInfo_1 = __importDefault(require("./Infos/KeyInfo"));
class EnclaveEntry {
    /**
     * @param {string} username
     * @param {string} persona
     * @param {bigint} expired
     * @param {KeyInfo} userInfo
     * @param {(0|1)[]} orksBitwise
     * @param {string[]} selfRequesti
     * @param {Uint8Array} sessKey
     */
    constructor(username, persona, expired, userInfo, orksBitwise, selfRequesti, sessKey) {
        this.username = username;
        this.persona = persona;
        this.expired = expired;
        this.userInfo = userInfo;
        this.orksBitwise = orksBitwise;
        this.selfRequesti = selfRequesti;
        this.sessKey = sessKey;
    }
    toString() {
        return JSON.stringify({
            username: this.username,
            persona: this.persona,
            expired: this.expired.toString(),
            userInfo: this.userInfo.toNativeTypeObject(),
            orksBitwise: JSON.stringify(this.orksBitwise),
            selfRequesti: this.selfRequesti,
            sessKey: (0, Serialization_1.bytesToBase64)(this.sessKey)
        });
    }
    static from(data) {
        const json = JSON.parse(data);
        const expired = BigInt(json.expired);
        const userInfo = KeyInfo_1.default.fromNativeTypeObject(json.userInfo); // includes uid + gCMK, ork URL + id + pubs 
        const orksBitwise = JSON.parse(json.orksBitwise);
        const selfRequesti = json.selfRequesti;
        const sessKey = (0, Serialization_1.base64ToBytes)(json.sessKey);
        return new EnclaveEntry(json.username, json.persona, expired, userInfo, orksBitwise, selfRequesti, sessKey);
    }
}
exports.default = EnclaveEntry;
