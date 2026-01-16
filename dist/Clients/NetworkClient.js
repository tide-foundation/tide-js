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
const KeyInfo_1 = __importDefault(require("../Models/Infos/KeyInfo"));
const ClientBase_1 = __importDefault(require("./ClientBase"));
class NetworkClient extends ClientBase_1.default {
    /**
     * @param {string} url
     */
    constructor(url = null) {
        if (url == null)
            super(window.location.origin);
        else
            super(url); // no gaurantee that the home ork will be part of selected orks, we need a selected ork url here for uncommitted entries
    }
    async GetPayerUrl(payerPublic) {
        const response = await this._get(`/Network/Payment/Node/Urls/${payerPublic}`);
        const responseData = await this._handleError(response, "Get Some Orks");
        const urlArray = JSON.parse(responseData);
        const randomUrl = urlArray[Math.floor(Math.random() * urlArray.length)];
        return randomUrl;
    }
    /**
     *
     * @param {string} uid
     * @returns
     */
    async GetKeyInfo(uid) {
        const response = await this._get(`/Network/Authentication/Users/UserInfo/${uid}`);
        let responseData;
        try {
            responseData = await this._handleError(response, "Get Key Info");
        }
        catch {
            throw Error("simulator.invalidAccount");
        }
        return KeyInfo_1.default.from(responseData);
    }
}
exports.default = NetworkClient;
