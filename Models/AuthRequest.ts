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

import { StringToUint8Array } from "../Cryptide/Serialization";
export default class AuthRequest{
    keyId: string;
    purpose: string;
    keyPub: string;
    expiry: bigint;
    sessionId: string;
    clientDPoPKey: string | undefined;

    constructor(keyId: string, purpose: string, keyPub: string, expiry: bigint, sessionId: string = null, clientDPoPKey: string = null){
        this.keyId = keyId
        this.purpose = purpose
        this.keyPub = keyPub
        this.expiry = expiry // in seconds
        this.sessionId = sessionId
        this.clientDPoPKey = clientDPoPKey;
    }

    toUint8Array(){
        return StringToUint8Array(this.toString());
    }
    toString(){
        const json = {
            'User': this.keyId,
            'Purpose': this.purpose,
            'Key': this.keyPub,
            'Expiry': this.expiry.toString(),
            'SessionId': !this.sessionId ? "" : this.sessionId, // SessionId is optional (although mandatory for apps like keycloak)
            'ClientDPoPKey': this.clientDPoPKey ? this.clientDPoPKey : ""
        };
        return JSON.stringify(json);
    }

    static new(keyId: string, purpose: string, clientKey: string, expiry: bigint, sessionId: string = null, clientDPoPKey:string = null){
        return new AuthRequest(keyId, purpose, clientKey, expiry, sessionId, clientDPoPKey); // 30 seconds
    }

    static from(data: string){
        const json = JSON.parse(data);
        return new AuthRequest(json.User, json.Purpose, json.Key, BigInt(json.Expiry), json.SessionId, json.ClientDPoPKey);
    }
}