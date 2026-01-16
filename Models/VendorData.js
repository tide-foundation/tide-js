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

import { Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import AuthRequest from "./AuthRequest.js";
export default class VendorData{
    /**
     * 
     * @param {string} VUID 
     * @param {Point} gCMKAuth 
     * @param {string} blindSig
     * @param {AuthRequest} AuthToken 
     */
    constructor(VUID, gCMKAuth, blindSig, AuthToken){
        this.VUID = VUID
        this.gCMKAuth = gCMKAuth
        this.blindSig = blindSig
        this.AuthToken = AuthToken
    }

    toString(){
        return JSON.stringify({
            'VUID': this.VUID,
            'gCMKAuth': new Ed25519PublicComponent(this.gCMKAuth).Serialize().ToString(),
            'blindSig': this.blindSig,
            'AuthToken': this.AuthToken.toString()
        })
    }

    static from(data){
        const json = JSON.parse(data);
        return new VendorData(json.VUID, json.gCMKAuth, json.blindSig, AuthRequest.from(json.AuthToken));
    }
}