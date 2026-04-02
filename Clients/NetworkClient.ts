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

import { Point } from "../Cryptide/Ed25519";
import { base64ToBytes, deserializeBitArray } from "../Cryptide/Serialization";
import { verifyRaw } from "../Cryptide/Signing/EdDSA";
import KeyInfo from "../Models/Infos/KeyInfo";
import OrkInfo from "../Models/Infos/OrkInfo";
import { sortORKs } from "../Tools/Utils";
import ClientBase from "./ClientBase"

export default class NetworkClient extends ClientBase {
    constructor(url: string = null){
        if(url == null) super(window.location.origin);
        else super(url); // no gaurantee that the home ork will be part of selected orks, we need a selected ork url here for uncommitted entries
        
    }

    async FindReservers(uid: string): Promise<OrkInfo[]> {
        const response = await this._get(`/Network/Authentication/Users/GetReservers/${uid}`);
        try{
            const responseData = await this._handleError(response, "Find Reservers");
            const formattedResponse = JSON.parse(responseData);
            if(formattedResponse.length == 0) throw Error("Username forbidden");
            const returnedResponse = formattedResponse.map(orkEntry => OrkInfo.from(orkEntry));
            return returnedResponse; 
        }catch(err){
            throw Error(err)
        }
    }

    async GetSomeORKs(){
        const response = await this._get('/Network/Authentication/Node/Some');
        const responseData = await this._handleError(response, "Get Some Orks");
        const formattedResponse = JSON.parse(responseData)
        const returnedResponse = formattedResponse.map(orkEntry => {
            return OrkInfo.from(orkEntry);
        });
        return returnedResponse;
    }

    async GetPayerUrl(payerPublic) {
        const response = await this._get(`/Network/Payment/Node/Urls/${payerPublic}`);
        const responseData = await this._handleError(response, "Get Payer URL");
        const urlArray = JSON.parse(responseData);
        const randomUrl = urlArray[Math.floor(Math.random() * urlArray.length)];
        return randomUrl;
    }

    async GetKeyInfo(uid: string){
        const response = await this._get(`/Network/Authentication/Users/UserInfo/${uid}`);
        let responseData;
        try{
            responseData = await this._handleError(response, "Get Key Info");
        }catch{
            throw Error("simulator.invalidAccount");
        }
        const keyInfo = KeyInfo.from(responseData);

        // Verify accountability signature
        const sortedOrks = sortORKs(keyInfo.OrkInfo);
        const bitArray = deserializeBitArray(keyInfo.OrksBitwise);
        let markedOrkPublicSum = Point.ZERO;
        for(let i = 0; i < sortedOrks.length; i++){
            if(bitArray[i] === 1){
                markedOrkPublicSum = markedOrkPublicSum.add(sortedOrks[i].orkPublic);
            }
        }
        const accountableKey = keyInfo.UserPublic.add(markedOrkPublicSum);
        const M_bytes = base64ToBytes(keyInfo.UserM);
        const verified = await verifyRaw(keyInfo.CommitS, keyInfo.CommitR, accountableKey, M_bytes);
        if(!verified){
            throw new Error("UserInfo signature verification failed");
        }

        return keyInfo;
    }
}