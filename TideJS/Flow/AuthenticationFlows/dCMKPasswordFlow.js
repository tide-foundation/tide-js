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
import {DH, Interpolation, Point} from "../../../Cryptide/index.js";
import { AuthenticateBasicReply, AuthenticateConsentReply, CmkConvertReply, PreSignInCVKReply, PrismConvertReply, SignInCVKReply } from "../../Math/KeyAuthentication.js";
import CMKConvertResponse from "../../Models/Responses/KeyAuth/Convert/CMKConvertResponse.js";
import PrismConvertResponse from "../../Models/Responses/KeyAuth/Convert/PrismConvertResponse.js";
import OrkInfo from "../../Models/Infos/OrkInfo.js";
import { TideJWT } from "../../index.js";
import { Math } from "../../../Cryptide/index.js";
import { Max, Threshold, WaitForNumberofORKs, sortORKs } from "../../Tools/Utils.js";
import { RandomBigInt } from "../../../Cryptide/Math.js";
import { BigIntFromByteArray, GetUID, Hex2Bytes, base64ToBytes, bitArrayToUint8Array, serializeBitArray, uint8ArrayToBitArray } from "../../../Cryptide/Serialization.js";
import EnclaveEntry from "../../Models/EnclaveEntry.js";
import VoucherFlow from "../VoucherFlows/VoucherFlow.js";
import KeyInfo from "../../Models/Infos/KeyInfo.js";

export default class dCMKPasswordFlow{
    /**
     * @param {KeyInfo} keyInfo
     * @param {string} sessID
     * @param {boolean} cmkCommitted
     * @param {boolean} prismCommitted
     * @param {string} voucherURL
     * @param {string} purpose
     */
    constructor(keyInfo, sessID, cmkCommitted, prismCommitted, voucherURL, purpose=null) {
        this.keyInfo = new KeyInfo(keyInfo.UserId, keyInfo.UserPublic, keyInfo.UserM, keyInfo.OrkInfo.slice());
        this.sessID = sessID;
        this.keyInfo.OrkInfo = sortORKs(this.keyInfo.OrkInfo);
        this.cmkCommitted = cmkCommitted
        this.prismCommitted = prismCommitted
        this.voucherURL = voucherURL
        this.purpose = purpose == null ? "auth" : purpose

        this.cState = undefined;
}

    /**
     * @param {bigint} sessKey
     * @param {Point} gSessKeyPub
     * @param {Point} gPass 
     * @param {Point} gCMK
     * @param {boolean} rememberMe
     */
    async Convert(sessKey, gSessKeyPub, gPass, gCMK, rememberMe){
        const clients = this.keyInfo.OrkInfo.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const voucherFlow = new VoucherFlow(this.keyInfo.OrkInfo.map(o => o.orkPaymentPublic), this.voucherURL, "signin");
        const {vouchers, k} = await voucherFlow.GetVouchers();

        const r1 = Math.RandomBigInt();
        const gBlurPass = gPass.blur(r1);

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map((client, i) => client.Convert(i, this.keyInfo.UserId, gBlurPass, gSessKeyPub, rememberMe, vouchers.toORK(i), this.keyInfo.UserM, this.cmkCommitted, this.prismCommitted));
        
        // To save time
        const prkECDHi = await DH.generateECDHi(this.keyInfo.OrkInfo.map(o => o.orkPublic), sessKey);
        
        const {fulfilledResponses, bitwise} = await WaitForNumberofORKs(this.keyInfo.OrkInfo, pre_ConvertResponses, "CMK", Threshold, null, prkECDHi);

        const ids = this.keyInfo.OrkInfo.map(c => BigInt(c.orkID));
        const {prismAuthis, timestampi, selfRequesti, expired} = await PrismConvertReply(
            fulfilledResponses.map(c => c.PrismConvertResponse), 
            ids,  
            this.keyInfo.OrkInfo.map(c => c.orkPublic), 
            r1,
            prkECDHi);

        this.cState = {
            selfRequesti,
            expired,
            bitwise,
            prkECDHi,
            ... await CmkConvertReply(
                fulfilledResponses.map(c => c.CMKConvertResponse), 
                ids, 
                prismAuthis, 
                gCMK, 
                timestampi, 
                this.sessID, 
                this.purpose,
                Point.from(Hex2Bytes(vouchers.qPub).slice(-32)), // to translate between tide component and native object
                BigIntFromByteArray(base64ToBytes(vouchers.UDeObf).slice(-32)), // to translate between tide component and native object
                k.GetPrivateKey()
            )
        }
        return {
            VUID: this.cState.VUID
        }
    }
    /**
     * 
     * @param {Uint8Array} sessKey 
     * @param {Point} gSessKeyPub 
     * @param {Point} gPass 
     */
    async ConvertPassword(sessKey, gSessKeyPub, gPass){
        if(this.cState != undefined) throw Error("This function must be called as a standlone in this flow");

        const r1 = RandomBigInt();
        const gBlurPass = gPass.blur(r1);

        const clients = this.keyInfo.OrkInfo.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const voucherFlow = new VoucherFlow(this.keyInfo.OrkInfo.map(o => o.orkPaymentPublic), this.voucherURL, "updateaccount");
        const {vouchers} = await voucherFlow.GetVouchers();

        const pre_convertPassResponses = clients.map((client, i) => client.ConvertPass(i, this.keyInfo.UserId, gBlurPass, gSessKeyPub, vouchers.toORK(i), this.keyInfo.UserM));
        
        // To save time
        const prkECDHi = await DH.generateECDHi(this.keyInfo.OrkInfo.map(o => o.orkPublic), sessKey);
        
        const { fulfilledResponses, bitwise } = await WaitForNumberofORKs(this.keyInfo.OrkInfo, pre_convertPassResponses, "CMK", Threshold, null, prkECDHi);

        const {prismAuthis, timestampi, selfRequesti, expired} = await PrismConvertReply(
            fulfilledResponses, 
            this.keyInfo.OrkInfo.map(c => BigInt(c.orkID)),  
            this.keyInfo.OrkInfo.map(c => c.orkPublic), 
            r1, 
            prkECDHi);
        
        return {
            bitwise: bitwise,
            expired,
            selfRequesti
        }
    }

    /**
     * @param {Point} gVRK
     * @param {Uint8Array} sessKey
     * @param {string} consentToSign
     */
    async Authenticate(gVRK, sessKey=null, consentToSign=null){
        if(this.cState == undefined) throw Error("Convert State is undefined");
        const cmkClients = this.keyInfo.OrkInfo.map(ork => new NodeClient(ork.orkURL))

        const pre_encSig = cmkClients.map((client, i) => client.Authenticate(
            this.keyInfo.UserId, 
            this.cState.selfRequesti[i], 
            this.cState.blurHCMKMul,
            serializeBitArray(this.cState.bitwise),
            this.cmkCommitted, 
            this.prismCommitted));

        const encSig = await Promise.all(pre_encSig);
        let vendorEncryptedData;
        if(consentToSign == null){
            vendorEncryptedData = await AuthenticateBasicReply(
                this.cState.VUID, 
                this.cState.prkECDHi, 
                encSig, 
                this.cState.gCMKAuth, 
                this.cState.authToken, 
                this.cState.r4, 
                this.cState.gRMul, 
                gVRK
            );
        }else{
            vendorEncryptedData = await AuthenticateConsentReply(
                this.cState.VUID, 
                this.cState.prkECDHi, 
                encSig, 
                this.cState.gCMKAuth, 
                this.cState.authToken, 
                this.cState.r4, 
                this.cState.gRMul, 
                gVRK,
                BigIntFromByteArray(sessKey),
                consentToSign
            );
        } 
        return {
            bitwise: this.cState.bitwise,
            expired: this.cState.expired,
            selfRequesti: this.cState.selfRequesti,
            vendorEncryptedData: vendorEncryptedData
        }
    }
}