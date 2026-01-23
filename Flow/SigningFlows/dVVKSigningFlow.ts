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

import BaseTideRequest from "../../Models/BaseTideRequest";
import { Max, Threshold, WaitForNumberofORKs, sortORKs } from "../../Tools/Utils";
import NodeClient from "../../Clients/NodeClient";
import OrkInfo from "../../Models/Infos/OrkInfo";
import { PreSign, Sign as SumS } from "../../Math/KeySigning";
import { BigIntToByteArray, ConcatUint8Arrays, serializeBitArray } from "../../Cryptide/Serialization";
import VoucherFlow from "../VoucherFlows/VoucherFlow";
import { Doken } from "../../Models/Doken";
import TideKey from "../../Cryptide/TideKey";

export default class dVVKSigningFlow {
    vvkid: any;
    vvkPublic: any;
    orks: any;
    sessKey: any;
    doken: any;
    getVouchersFunction: any;
    voucherURL: any;
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
        this.orks = sortORKs(this.orks); // sort for bitwise!

        if(doken){
            if(!doken.payload.sessionKey.Equals(sessKey.get_public_component())) throw Error("Mismatch between session key private and Doken session key public");
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

        const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "vendorsign");
        const pre_vouchers = voucherFlow.GetVouchers(this.getVouchersFunction);

        const pre_clients = this.orks.map(info => new NodeClient(info.orkURL).AddBearerAuthorization(this.sessKey.get_private_component().rawBytes, this.sessKey.get_public_component().Serialize().ToString(), this.doken).EnableTideDH(info.orkPublic));
        const clients = await Promise.all(pre_clients); 

        const { vouchers } = await pre_vouchers;

        const pre_PreSignResponses = clients.map((client, i) => client.PreSign(i, this.vvkid, request, vouchers.toORK(i)));
        const { fulfilledResponses, bitwise } = await WaitForNumberofORKs(this.orks, pre_PreSignResponses, "VVK", waitForAll ? Max : Threshold, null, clients);
        const GRj = PreSign(fulfilledResponses.map(f => f.GRis));

        const pre_SignResponses = clients.map((client, i) => client.Sign(this.vvkid, request, GRj, serializeBitArray(bitwise)));
        const SignResponses = await Promise.all(pre_SignResponses);
        const Sj = SumS(SignResponses.map(s => s.Sij));

        if (GRj.length != Sj.length) throw Error("Weird amount of GRjs and Sjs");
        let sigs = [];
        for (let i = 0; i < GRj.length; i++) {
            sigs.push(ConcatUint8Arrays([GRj[i].toRawBytes(), BigIntToByteArray(Sj[i])]));
        }

        return sigs;
    }
}
