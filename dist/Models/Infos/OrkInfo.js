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
const Ed25519_1 = require("../../Cryptide/Ed25519");
const Serialization_1 = require("../../Cryptide/Serialization");
class OrkInfo {
    /**
     *
     * @param {string} orkID
     * @param {Point} orkPublic
     * @param {string} orkURL
     * @param {Point} orkPaymentPublic
     */
    constructor(orkID, orkPublic, orkURL, orkPaymentPublic) {
        this.orkID = orkID;
        this.orkPublic = orkPublic;
        this.orkURL = orkURL;
        this.orkPaymentPublic = orkPaymentPublic;
    }
    toString() {
        return JSON.stringify({
            Id: this.orkID,
            PublicKey: this.orkPublic.toBase64(),
            URL: this.orkURL,
            PaymentPublicKey: this.orkPaymentPublic.toBase64()
        });
    }
    toNativeTypeObject() {
        return {
            Id: this.orkID,
            PublicKey: this.orkPublic.toBase64(),
            URL: this.orkURL,
            PaymentPublicKey: this.orkPaymentPublic.toBase64()
        };
    }
    static fromNativeTypeObject(json) {
        return new OrkInfo(json.Id, Ed25519_1.Point.fromBase64(json.PublicKey), json.URL, Ed25519_1.Point.fromBase64(json.PaymentPublicKey));
    }
    static from(json) {
        const { publickey, paymentpublickey, id, url } = normalizeKeys(json);
        const pub = Ed25519_1.Point.fromBytes((0, Serialization_1.Hex2Bytes)(publickey).slice(3));
        const paymentPub = Ed25519_1.Point.fromBytes((0, Serialization_1.Hex2Bytes)(paymentpublickey).slice(3));
        return new OrkInfo(id, pub, url, paymentPub);
    }
}
exports.default = OrkInfo;
function normalizeKeys(obj) {
    const normalized = {};
    Object.keys(obj).forEach(key => {
        normalized[key.toLowerCase()] = obj[key];
    });
    return normalized;
}
