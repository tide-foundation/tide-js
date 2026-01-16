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
exports.AuthorizedSigningFlow = AuthorizedSigningFlow;
const BaseTideRequest_1 = __importDefault(require("../../Models/BaseTideRequest"));
const dVVKSigningFlow_1 = __importDefault(require("../SigningFlows/dVVKSigningFlow"));
/**
 *
 * @param {{
* vendorId: string,
* token: Doken,
* sessionKey: TideKey
* voucherURL: string,
* homeOrkUrl: string | null
* keyInfo: KeyInfo
* }} config
*/
function AuthorizedSigningFlow(config) {
    if (!(this instanceof AuthorizedSigningFlow)) {
        throw new Error("The 'AuthorizedSigningFlow' constructor must be invoked with 'new'.");
    }
    if (config.token) {
        if (!config.token.payload.sessionKey.Equals(config.sessionKey.get_public_component()))
            throw Error("Mismatch between session key private and Doken session key public");
    }
    var signingFlow = this;
    signingFlow.vvkId = config.vendorId;
    signingFlow.token = config.token;
    signingFlow.voucherURL = config.voucherURL;
    signingFlow.sessKey = config.sessionKey;
    signingFlow.vvkInfo = config.keyInfo;
    /**
     * @param {Uint8Array} tideSerializedRequest
     * @param {bool} waitForAll
     */
    signingFlow.signv2 = async function (tideSerializedRequest, waitForAll) {
        const flow = new dVVKSigningFlow_1.default(this.vvkId, signingFlow.vvkInfo.UserPublic, signingFlow.vvkInfo.OrkInfo, signingFlow.sessKey, signingFlow.token, this.voucherURL);
        return flow.start(BaseTideRequest_1.default.decode(tideSerializedRequest), waitForAll);
    };
}
