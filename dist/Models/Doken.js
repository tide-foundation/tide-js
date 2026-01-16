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
exports.Doken = Doken;
const index_1 = require("../index");
const BaseComponent_1 = require("../Cryptide/Components/BaseComponent");
const Ed25519Components_1 = require("../Cryptide/Components/Schemes/Ed25519/Ed25519Components");
const Serialization_1 = require("../Cryptide/Serialization");
const TideKey_1 = __importDefault(require("../Cryptide/TideKey"));
const Utils_1 = require("../Tools/Utils");
// Define DokenPayload class first so it can be used in Doken constructor
class DokenPayload {
    constructor(json) {
        var s = BaseComponent_1.BaseComponent.DeserializeComponent(json["t.ssk"]);
        if (s instanceof Ed25519Components_1.Ed25519PublicComponent) {
            this.sessionKey = s;
        }
        else
            throw Error("Unexpected session key type");
        var u = BaseComponent_1.BaseComponent.DeserializeComponent(json["tideuserkey"]);
        if (u instanceof Ed25519Components_1.Ed25519PublicComponent) {
            this.tideuserkey = u;
        }
        else
            throw Error("Unexpected tide user key type");
        if (typeof json.vuid === "string")
            this.vuid = json.vuid;
        else
            throw Error("Expected vuid to be string");
        if (typeof json["t.uho"] === "string")
            this.homeOrk = json["t.uho"];
        else
            throw Error("Expected user home to be string");
        // Will be affected by 2032 problem
        if (typeof json.exp === "number")
            this.exp = json.exp;
        else
            throw Error("Expected exp to be a number");
        if (typeof json.aud === "string")
            this.aud = json.aud;
        else
            throw Error("Expected aud to be string");
        if (typeof json.realm_access === "object")
            this.realm_access = json.realm_access;
        else if (!json.realm_access)
            this.realm_access = null;
        else
            throw Error("Expected realm_access to be string");
        if (typeof json.resource_access === "object")
            this.resource_access = json.resource_access;
        else if (!json.resource_access)
            this.resource_access = null;
        else
            throw Error("Expected resource_access to be string");
    }
    serialize() {
        return JSON.stringify({
            "tideuserkey": this.tideuserkey.Serialize().ToString(),
            "t.ssk": this.sessionKey.Serialize().ToString(),
            "vuid": this.vuid,
            "t.uho": this.homeOrk,
            "exp": this.exp,
            "aud": this.aud,
            "realm_access": this.realm_access,
            "resource_access": this.resource_access
        });
    }
}
/**
 *
 * @param {string} data
 */
function Doken(data) {
    if (!(this instanceof Doken)) {
        throw new Error("The 'Doken' constructor must be invoked with 'new'.");
    }
    let doken = this;
    doken.dataRef = undefined;
    doken.header = undefined;
    doken.payload = undefined;
    doken.signature = undefined;
    const parts = data.split(".");
    if (parts.length != 3)
        throw Error("Doken must be a 3 part token (including signature)");
    doken.dataRef = data.slice(0);
    doken.header = JSON.parse((0, Serialization_1.StringFromUint8Array)((0, Serialization_1.base64ToBytes)((0, Serialization_1.base64UrlToBase64)(parts[0]))));
    doken.payload = new DokenPayload(JSON.parse((0, Serialization_1.StringFromUint8Array)((0, Serialization_1.base64ToBytes)((0, Serialization_1.base64UrlToBase64)(parts[1])))));
    doken.signature = (0, Serialization_1.base64ToBytes)((0, Serialization_1.base64UrlToBase64)(parts[2]));
    doken.isExpired = function () {
        return this.payload.exp < (0, Utils_1.CurrentTime)();
    };
    doken.setNewSessionKey = function (sessionKey) {
        const temp = doken.dataRef.split(".");
        let payload = (0, Serialization_1.StringFromUint8Array)((0, Serialization_1.base64ToBytes)((0, Serialization_1.base64UrlToBase64)(parts[1])));
        payload = payload.replace(/("t.ssk"\s*:\s*)"[^"]*"/, `$1"${sessionKey}"`);
        // WE DO ALL THESE MANUAL UPDATES BECAUSE JAVASCRIPT DOES NOT GUARANTEE ORDER IN JSON
        // SINCE WE DON'T SEND THE DOKEN TO GET SIGNED, WE CONTRCUST THE MESSAGE HERE
        // WE NEED TO ENSURE ITS THE SAME THING THE ORK SIGNS
        doken.dataRef = temp[0] + "." + (0, Serialization_1.base64ToBase64Url)((0, Serialization_1.bytesToBase64)((0, Serialization_1.StringToUint8Array)(payload))) + (temp.length > 2 ? "." + temp[2] : ""); // update encoded string
        doken.payload.sessionKey = BaseComponent_1.BaseComponent.DeserializeComponent(sessionKey); // update session key object in payload
    };
    doken.setNewSignature = function (sig) {
        doken.signature = sig.slice(); // update sig object
        const temp = doken.dataRef.split(".");
        doken.dataRef = temp[0] + "." + temp[1] + "." + (0, Serialization_1.base64ToBase64Url)((0, Serialization_1.bytesToBase64)(doken.signature)); // update dataref object
    };
    /**
     *
     * @param {TideKey} sessionKeyToCheck
     */
    doken.validate = function (sessionKeyToCheck = null) {
        // When an error is thrown - its a criticial error so the whole page should stop
        // But if validation just fails, then we return false with a reason why
        if (doken.header.alg != "EdDSA")
            throw Error("Doken header alg expected to be EdDSA but got " + doken.header.alg);
        if (doken.header.typ != "doken")
            throw Error("Doken header typ expected to be doken but got " + doken.header.typ);
        // Check expiry
        if (index_1.Utils.CurrentTime() > doken.payload.exp)
            return { success: false, reason: "expired" };
        // Check session key matches
        if (sessionKeyToCheck) {
            if (!sessionKeyToCheck.get_public_component().Equals(doken.payload.sessionKey))
                return { success: false, reason: `sessionkey mismatch. actual: ${sessionKeyToCheck.get_public_component().Serialize().ToString()}. expected: ${doken.payload.sessionKey.Serialize().ToString()}` };
        }
        return { success: true };
    };
    /**
     *
     * @param {Ed25519PublicComponent} vendorPublic
     */
    doken.verify = async function (vendorPublic) {
        return new TideKey_1.default(vendorPublic).verify((0, Serialization_1.StringToUint8Array)(this.dataRef), this.signature);
    };
    /**
     *
     * @returns {string}
     */
    doken.serialize = function () {
        return doken.dataRef;
    };
}
