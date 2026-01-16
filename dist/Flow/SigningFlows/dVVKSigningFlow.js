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
const KeySigning_1 = require("../../Math/KeySigning");
const Serialization_1 = require("../../Cryptide/Serialization");
const VoucherFlow_1 = __importDefault(require("../VoucherFlows/VoucherFlow"));
class dVVKSigningFlow {
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
        if (doken) {
            if (!doken.payload.sessionKey.Equals(sessKey.get_public_component()))
                throw Error("Mismatch between session key private and Doken session key public");
            this.doken = doken.serialize();
        }
        this.sessKey = sessKey;
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
        const voucherFlow = new VoucherFlow_1.default(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "vendorsign");
        const pre_vouchers = voucherFlow.GetVouchers(this.getVouchersFunction);
        const pre_clients = this.orks.map(info => new NodeClient_1.default(info.orkURL).AddBearerAuthorization(this.sessKey.get_private_component().rawBytes, this.sessKey.get_public_component().Serialize().ToString(), this.doken).EnableTideDH(info.orkPublic));
        const clients = await Promise.all(pre_clients);
        const { vouchers } = await pre_vouchers;
        const pre_PreSignResponses = clients.map((client, i) => client.PreSign(i, this.vvkid, request, vouchers.toORK(i)));
        const { fulfilledResponses, bitwise } = await (0, Utils_1.WaitForNumberofORKs)(this.orks, pre_PreSignResponses, "VVK", waitForAll ? Utils_1.Max : Utils_1.Threshold, null, clients);
        const GRj = (0, KeySigning_1.PreSign)(fulfilledResponses.map(f => f.GRis));
        const pre_SignResponses = clients.map((client, i) => client.Sign(this.vvkid, request, GRj, (0, Serialization_1.serializeBitArray)(bitwise)));
        const SignResponses = await Promise.all(pre_SignResponses);
        const Sj = (0, KeySigning_1.Sign)(SignResponses.map(s => s.Sij));
        if (GRj.length != Sj.length)
            throw Error("Weird amount of GRjs and Sjs");
        let sigs = [];
        for (let i = 0; i < GRj.length; i++) {
            sigs.push((0, Serialization_1.ConcatUint8Arrays)([GRj[i].toRawBytes(), (0, Serialization_1.BigIntToByteArray)(Sj[i])]));
        }
        return sigs;
    }
}
exports.default = dVVKSigningFlow;
