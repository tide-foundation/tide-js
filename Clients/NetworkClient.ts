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

import KeyInfo from "../Models/Infos/KeyInfo";
import OrkInfo from "../Models/Infos/OrkInfo";
import ClientBase from "./ClientBase"
import { TideError } from "../Errors/TideError";
import { TideJsErrorCodes } from "../Errors/codes";

export default class NetworkClient extends ClientBase {
    constructor(url: string = null){
        if(url == null) super(window.location.origin);
        else super(url); // no gaurantee that the home ork will be part of selected orks, we need a selected ork url here for uncommitted entries

    }

    async FindReservers(uid: string): Promise<OrkInfo[]> {
        const endpoint = `/Network/Authentication/Users/GetReservers/${uid}`;
        const response = await this._get(endpoint);
        try{
            const responseData = await this._handleError(response, "Find Reservers");
            const formattedResponse = JSON.parse(responseData);
            if(formattedResponse.length == 0) throw new TideError({
                code: TideJsErrorCodes.VAL_UID_FORBIDDEN,
                displayMessage: `Username forbidden (uid prefix=${(uid ?? '').slice(0, 12)}, endpoint=${endpoint ?? this.url})`,
                source: "Clients/NetworkClient.ts:34",
            });
            const returnedResponse = formattedResponse.map(orkEntry => OrkInfo.from(orkEntry));
            return returnedResponse;
        }catch(err){
            // If it's already a TideError, propagate verbatim — don't lose code/url/cause.
            throw err;
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
        }catch(err){
            throw new TideError({
                code: TideJsErrorCodes.VAL_INVALID_ACCOUNT,
                displayMessage: "simulator.invalidAccount",   // preserve the sentinel string in displayMessage for any callers matching on .message
                source: "Clients/NetworkClient.ts:66",
                cause: err,                                   // preserve the upstream TideError if there is one
            });
        }
        return KeyInfo.from(responseData);
    }
}