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
const Serialization_1 = require("../Cryptide/Serialization");
class AuthRequest {
    /**
     *
     * @param {string} keyId
     * @param {string} purpose
     * @param {string} keyPub
     * @param {bigint} expiry
     * @param {string} sessionId
     */
    constructor(keyId, purpose, keyPub, expiry, sessionId = null) {
        this.keyId = keyId;
        this.purpose = purpose;
        this.keyPub = keyPub;
        this.expiry = expiry; // in seconds
        this.sessionId = sessionId;
    }
    toUint8Array() {
        return (0, Serialization_1.StringToUint8Array)(this.toString());
    }
    toString() {
        const json = {
            'User': this.keyId,
            'Purpose': this.purpose,
            'Key': this.keyPub,
            'Expiry': this.expiry.toString(),
            'SessionId': !this.sessionId ? "" : this.sessionId // SessionId is optional (although mandatory for apps like keycloak)
        };
        return JSON.stringify(json);
    }
    /**
     * @param {string} keyId
     * @param {string} purpose
     * @param {string} clientKey
     * @param {bigint} expiry
     * @param {string} sessionId
     * @returns
     */
    static new(keyId, purpose, clientKey, expiry, sessionId = null) {
        return new AuthRequest(keyId, purpose, clientKey, expiry, sessionId); // 30 seconds
    }
    static from(data) {
        const json = JSON.parse(data);
        return new AuthRequest(json.User, json.Purpose, json.Key, BigInt(json.Expiry), json.SessionId);
    }
}
exports.default = AuthRequest;
