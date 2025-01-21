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

import { Point } from "../../Cryptide/index.js";
import { BigIntFromByteArray, BigIntToByteArray, ConcatUint8Arrays, StringFromUint8Array, StringToUint8Array, base64ToBase64Url, base64ToBytes, base64UrlToBase64, bytesToBase64 } from "../../Cryptide/Serialization.js";
import { CurrentTime } from "../Tools/Utils.js";
import { EdDSA } from "../../Cryptide/index.js";

export default class TideJWT{
    /**
     * 
     * @param {string} uid 
     * @param {bigint} expTime 
     * @param {Point} gSessKeyPub
     * @param {string} gVVK
     */
    static new(uid, expTime, gSessKeyPub, gVVK){
        const header = {
            'alg': "EdDSA",
            'typ': "JWT"
        }
        const payload = {
            'uid': uid,
            'exp': Number(expTime.toString()),
            'gSessKeyPub': gSessKeyPub.toBase64(),
            'gVVK': gVVK
        }
        const jwt = base64ToBase64Url(bytesToBase64(StringToUint8Array(JSON.stringify(header)))) + "." + base64ToBase64Url(bytesToBase64(StringToUint8Array(JSON.stringify(payload))));
        return jwt; // this jwt has no signature as it was just created
    }

    static getUID(jwt){
        var p = jwt.split(".")[1];
        return JSON.parse(atob(base64UrlToBase64(p))).uid;
    }

    static getGVVK(jwt){
        var p = jwt.split(".")[1];
        return JSON.parse(atob(base64UrlToBase64(p))).gVVK;
    }

    /**
     * 
     * @param {string} jwt 
     * @param {bigint} S 
     * @param {Point} R 
     */
    static addSignature(jwt, S, R){
        return jwt + "." + base64ToBase64Url(bytesToBase64(ConcatUint8Arrays([R.toArray(), BigIntToByteArray(S)])));
    }

    /**
     * @param {string} jwt 
     * @param {Point} pub 
     */
    static async verify(jwt, pub){
        const strings = jwt.split(".");
        const dataToVerify = StringToUint8Array(strings[0] + "." + strings[1]);
        const sig = base64UrlToBase64(strings[2]);
        return await EdDSA.verify(sig, pub, dataToVerify);
    }

    /**
     * @param {string} jwt 
     */
    static checkExp(jwt){
        try{
            const parts = jwt.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid JWT token format');
            }

            const payload = parts[1];
            const decodedPayload = StringFromUint8Array(base64ToBytes(base64UrlToBase64(payload)));
            const payloadObj = JSON.parse(decodedPayload);

            const exp = payloadObj.exp;
            if (!exp) {
                throw new Error('Expiration time is missing in the JWT token');
            }
            return CurrentTime() < exp; // comparing a number to an string - because JS doesn't care
        }catch(error){
            console.log("Error in checking expiry: " + error.message)
            return false;
        }
    }

    /**
     * @param {string} jwt 
     * @param {string} sessKey 
     */
    static checkSessKeyToJWT(jwt, sessKey){
        try{
            if(jwt == null || sessKey == null) return false;
            
            const parts = jwt.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid JWT token format');
            }

            const payload = parts[1];
            const decodedPayload = StringFromUint8Array(base64ToBytes(base64UrlToBase64(payload)));
            const payloadObj = JSON.parse(decodedPayload);

            const gSessKeyPub = Point.fromB64(payloadObj.gSessKeyPub);
            const privateKey = BigIntFromByteArray(base64ToBytes(sessKey));
            const pointToTest = Point.g.times(privateKey);

            return gSessKeyPub.isEqual(pointToTest);
        }catch(error){
            console.log("Error in checking expiry: " + error.message)
            return false;
        }
    }
}