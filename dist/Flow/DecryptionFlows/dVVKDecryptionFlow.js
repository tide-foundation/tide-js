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
const Utils_1 = require("../../Tools/Utils");
const NodeClient_1 = __importDefault(require("../../Clients/NodeClient"));
const VoucherFlow_1 = __importDefault(require("../VoucherFlows/VoucherFlow"));
const KeyDecryption_1 = require("../../Math/KeyDecryption");
class dVVKDecryptionFlow {
    /**
     * @param {string} vvkid
     * @param {Point} vvkPublic
     * @param {OrkInfo[]} orks
     * @param {TideKey} sessKey
     * @param {Doken} doken
     * @param {string} voucherURL
     */
    constructor(vvkid, vvkPublic, orks, sessKey, doken, voucherURL) {
        this.vvkid = vvkid;
        this.vvkPublic = vvkPublic;
        this.orks = orks;
        this.orks = (0, Utils_1.sortORKs)(this.orks); // sort for bitwise!
        if (!doken.payload.sessionKey.Equals(sessKey.get_public_component()))
            throw Error("Mismatch between session key private and Doken session key public");
        this.sessKey = sessKey;
        this.doken = doken;
        this.getVouchersFunction = null;
        this.voucherURL = voucherURL;
    }
    /**
     * @param {(request: string) => Promise<string> } getVouchersFunction
     * @returns {dVVKSigningFlow}
     */
    setVoucherRetrievalFunction(getVouchersFunction) {
        this.getVouchersFunction = getVouchersFunction;
        return this;
    }
    /**
     * @param {BaseTideRequest} request
     * @param {bool} waitForAll
     */
    async start(request, waitForAll = false) {
        const pre_clients = this.orks.map(info => new NodeClient_1.default(info.orkURL).AddBearerAuthorization(this.sessKey.get_private_component().rawBytes, this.sessKey.get_public_component().Serialize().ToString(), this.doken.serialize()).EnableTideDH(info.orkPublic));
        const voucherFlow = new VoucherFlow_1.default(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "vendordecrypt");
        const { vouchers } = await voucherFlow.GetVouchers(this.getVouchersFunction);
        const clients = await Promise.all(pre_clients); // to speed things up - computer shared key while grabbing vouchers
        const pre_PreDecryptResponses = clients.map((client, i) => client.Decrypt(i, this.vvkid, request, vouchers.toORK(i)));
        const { fulfilledResponses, bitwise } = await (0, Utils_1.WaitForNumberofORKs)(this.orks, pre_PreDecryptResponses, "VVK", waitForAll ? Utils_1.Max : Utils_1.Threshold, null, clients);
        return (0, KeyDecryption_1.GetKeys)(fulfilledResponses, this.orks.map(o => BigInt(o.orkID))); // to be used for symmetric encryption now with caller
    }
}
exports.default = dVVKDecryptionFlow;
