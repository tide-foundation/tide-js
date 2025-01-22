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

import VendorClient from "../Clients/VendorClient.js";
import { Point, ElGamal } from "../Cryptide/index.js"
export default class dDecryptionTestFlow{
    /**
     * @param {string} vendorUrl 
     * @param {Point} vendorPublic
     * @param {Point} userPublic
     * @param {string} userAuthJwt 
     * @param {string} cvkOrkUrl
     */
    constructor(vendorUrl, vendorPublic, userPublic, userAuthJwt, cvkOrkUrl){
        this.vendorUrl = vendorUrl;
        this.vendorPublic = vendorPublic;
        this.userPublic = userPublic;
        this.jwt = userAuthJwt;
        this.cvkOrkUrl = cvkOrkUrl;
    }

    async startTest(){
        const challenge = new Uint8Array(32);
        window.crypto.getRandomValues(challenge);
        const encryptedByGCVK = await ElGamal.encryptData(challenge, this.userPublic);
        const encryptedByGVVK = await ElGamal.encryptData(challenge, this.vendorPublic);

        const vendorClient = new VendorClient(this.vendorUrl);
        await vendorClient.DecryptionTest(encryptedByGCVK, encryptedByGVVK, this.jwt, this.cvkOrkUrl);
    }
}