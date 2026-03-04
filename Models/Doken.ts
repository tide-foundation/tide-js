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

import { Utils } from "../index";
import { BaseComponent } from "../Cryptide/Components/BaseComponent";
import { Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components";
import { base64ToBase64Url, base64ToBytes, base64UrlToBase64, bytesToBase64, StringFromUint8Array, StringToUint8Array } from "../Cryptide/Serialization";
import TideKey from "../Cryptide/TideKey";
import { CurrentTime } from "../Tools/Utils";

// Define DokenPayload class first so it can be used in Doken constructor
class DokenPayload{
    sessionKey: any;
    tideuserkey: any;
    vuid: any;
    homeOrk: any;
    exp: any;
    aud: any;
    realm_access: any;
    resource_access: any;

    constructor(json: any){
        var s = BaseComponent.DeserializeComponent(json["t.ssk"]);
        if(s instanceof Ed25519PublicComponent){
            this.sessionKey = s;
        }else throw Error("Unexpected session key type");

        var u = BaseComponent.DeserializeComponent(json["tideuserkey"]);
        if(u instanceof Ed25519PublicComponent){
            this.tideuserkey = u;
        }else throw Error("Unexpected tide user key type");

        if( typeof json.vuid === "string") this.vuid = json.vuid;
        else throw Error("Expected vuid to be string");

        if( typeof json["t.uho"] === "string") this.homeOrk = json["t.uho"];
        else throw Error("Expected user home to be string");

        // Will be affected by 2032 problem
        if( typeof json.exp === "number") this.exp = json.exp;
        else throw Error("Expected exp to be a number");

        if( typeof json.aud === "string") this.aud = json.aud;
        else throw Error("Expected aud to be string");

        if( typeof json.realm_access === "object") this.realm_access = json.realm_access;
        else if(!json.realm_access) this.realm_access = null;
        else throw Error("Expected realm_access to be string");

        if( typeof json.resource_access === "object") this.resource_access = json.resource_access;
        else if(!json.resource_access) this.resource_access = null;
        else throw Error("Expected resource_access to be string");
    }

    serialize(){
        return JSON.stringify({
            "tideuserkey": this.tideuserkey.Serialize().ToString(),
            "t.ssk": this.sessionKey.Serialize().ToString(),
            "vuid": this.vuid,
            "t.uho": this.homeOrk,
            "exp": this.exp,
            "aud": this.aud,
            "realm_access": this.realm_access,
            "resource_access": this.resource_access
        })
    }
}

export class Doken {
    dataRef: string;
    header: any;
    payload: DokenPayload;
    signature: Uint8Array;
    private parts: string[];

    constructor(data: string) {
        const parts = data.split(".");
        if(parts.length != 3) throw Error("Doken must be a 3 part token (including signature)");
        this.parts = parts;
        this.dataRef = data.slice(0);

        this.header = JSON.parse(StringFromUint8Array(base64ToBytes(base64UrlToBase64(parts[0]))));
        this.payload = new DokenPayload(JSON.parse(StringFromUint8Array(base64ToBytes(base64UrlToBase64(parts[1])))));
        this.signature = base64ToBytes(base64UrlToBase64(parts[2]));
    }

    isExpired(): boolean {
        return this.payload.exp < CurrentTime();
    }

    setNewSessionKey(sessionKey: string) {
        const temp = this.dataRef.split(".");
        let payload = StringFromUint8Array(base64ToBytes(base64UrlToBase64(this.parts[1])));

        payload = payload.replace(
            /("t.ssk"\s*:\s*)"[^"]*"/,
            `$1"${sessionKey}"`
        );

        // WE DO ALL THESE MANUAL UPDATES BECAUSE JAVASCRIPT DOES NOT GUARANTEE ORDER IN JSON
        // SINCE WE DON'T SEND THE DOKEN TO GET SIGNED, WE CONTRCUST THE MESSAGE HERE
        // WE NEED TO ENSURE ITS THE SAME THING THE ORK SIGNS
        this.dataRef = temp[0] + "." + base64ToBase64Url(bytesToBase64(StringToUint8Array(payload))) + (temp.length > 2 ? "." + temp[2] : ""); // update encoded string
        this.payload.sessionKey = BaseComponent.DeserializeComponent(sessionKey); // update session key object in payload
    }

    setNewSignature(sig: Uint8Array) {
        this.signature = sig.slice(); // update sig object

        const temp = this.dataRef.split(".");

        this.dataRef = temp[0] + "." + temp[1] + "." + base64ToBase64Url(bytesToBase64(this.signature)); // update dataref object
    }

    validate(sessionKeyToCheck: TideKey = null): {success: boolean, reason?: string} {
        // When an error is thrown - its a criticial error so the whole page should stop
        // But if validation just fails, then we return false with a reason why

        if(this.header.alg != "EdDSA") throw Error("Doken header alg expected to be EdDSA but got " + this.header.alg);
        if(this.header.typ != "doken") throw Error("Doken header typ expected to be doken but got " + this.header.typ);

        // Check expiry
        if(Utils.CurrentTime() > this.payload.exp) return {success: false, reason: "expired"}

        // Check session key matches
        if(sessionKeyToCheck){
            if(!sessionKeyToCheck.get_public_component().Equals(this.payload.sessionKey)) return {success: false, reason: `sessionkey mismatch. actual: ${sessionKeyToCheck.get_public_component().Serialize().ToString()}. expected: ${this.payload.sessionKey.Serialize().ToString()}`};
        }

        return {success: true}
    }

    async verify(vendorPublic: Ed25519PublicComponent) {
        return new TideKey(vendorPublic).verify(StringToUint8Array(this.dataRef), this.signature);
    }

    serialize(): string {
        return this.dataRef;
    }
}
