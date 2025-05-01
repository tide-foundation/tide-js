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

import NodeClient from "../../Clients/NodeClient.js";
import { DH, Interpolation } from "../../Cryptide/index.js";
import { AuthenticateBasicReply, CmkConvertReply, ConvertRememberedReply } from "../../Math/KeyAuthentication.js";
import { CurrentTime, Max, Threshold, WaitForNumberofORKs, sortORKs } from "../../Tools/Utils.js";
import EnclaveEntry from "../../Models/EnclaveEntry.js";
import { base64ToBytes, BigIntFromByteArray, Hex2Bytes, serializeBitArray, uint8ArrayToBitArray } from "../../Cryptide/Serialization.js";
import { GetPublic } from "../../Cryptide/Math.js";
import VoucherFlow from "../VoucherFlows/VoucherFlow.js";
import { Point } from "../../Cryptide/Ed25519.js";

export default class dCMKPasswordlessFlow {
    /**
     * @param {string} sessID
     * @param {EnclaveEntry} flowInitData 
     * @param {string} voucherURL
     */
    constructor(sessID, flowInitData, voucherURL) {
        this.sessID = sessID;

        if (flowInitData.expired < BigInt(CurrentTime())) throw Error("Please log in again.");
        this.uid = flowInitData.userInfo.UserId;
        this.selfRequesti = flowInitData.selfRequesti;
        this.bitwise = flowInitData.orksBitwise;
        this.orks = sortORKs(flowInitData.userInfo.OrkInfo).filter((_, i) => this.bitwise[i] == 1);
        this.userPublic = flowInitData.userInfo.UserPublic;
        this.sessKey = flowInitData.sessKey;
        this.gSessKeyPub = GetPublic(this.sessKey);
        this.voucherURL = voucherURL;

        this.cState = undefined;
        this.aState = undefined;
    }

    async ConvertRemembered() {
        const clients = this.orks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "signin");
        const { vouchers, k } = await voucherFlow.GetVouchers();

        const pre_ConvertAuthnResponses = clients.map((client, i) => client.ConvertRemembered(i, this.uid, this.selfRequesti[i], vouchers.toORK(i)));

        // To save time
        const prkECDHi = await DH.generateECDHi(this.orks.map(o => o.orkPublic), this.sessKey);

        const { fulfilledResponses, bitwise } = await WaitForNumberofORKs(this.orks, pre_ConvertAuthnResponses, "CMK", Threshold, this.bitwise, prkECDHi);

        this.cState = {
            bitwise,
            ... await ConvertRememberedReply(
                fulfilledResponses,
                this.orks.map(o => BigInt(o.orkID)),
                this.userPublic,
                this.sessID,
                prkECDHi,
                Point.fromBytes(Hex2Bytes(vouchers.qPub).slice(-32)), // to translate between tide component and native object
                BigIntFromByteArray(base64ToBytes(vouchers.UDeObf).slice(-32)), // to translate between tide component and native object
                k.get_private_component().priv)
        }
        return {
            VUID: this.cState.VUID
        }
    }

    /**
     * @param {Point} gVRK
     */
    async AuthenticateRemembered(gVRK) {
        if (this.cState == undefined) throw Error("Convert State is undefined");
        const cmkClients = this.orks.map(ork => new NodeClient(ork.orkURL))

        const pre_encSig = cmkClients.map((client, i) => client.AuthenticateRemembered(
            this.uid,
            this.cState.blurHCMKMul,
            serializeBitArray(this.cState.bitwise)
        ));

        const encSig = await Promise.all(pre_encSig);
        return await AuthenticateBasicReply(
            this.cState.VUID,
            this.cState.prkECDHi,
            encSig,
            this.cState.gCMKAuth,
            this.cState.authToken,
            this.cState.r4,
            this.cState.gRMul,
            gVRK
        );
    }
}