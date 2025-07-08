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
import {DH, Interpolation} from "../../Cryptide/index.js";
import { AuthenticateBasicReply, AuthenticateConsentReply, CmkConvertReply, PrismConvertReply  } from "../../Math/KeyAuthentication.js";
import { Math } from "../../Cryptide/index.js";
import { Max, Threshold, WaitForNumberofORKs, sortORKs } from "../../Tools/Utils.js";
import { RandomBigInt } from "../../Cryptide/Math.js";
import { BigIntFromByteArray, GetUID, Hex2Bytes, base64ToBytes, bitArrayToUint8Array, serializeBitArray, uint8ArrayToBitArray } from "../../Cryptide/Serialization.js";
import EnclaveEntry from "../../Models/EnclaveEntry.js";
import VoucherFlow from "../VoucherFlows/VoucherFlow.js";
import KeyInfo from "../../Models/Infos/KeyInfo.js";
import { Point } from "../../Cryptide/Ed25519.js";
import TideKey from "../../Cryptide/TideKey.js";

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
     * @param {TideKey} sessKey
     * @param {Point} gSessKeyPub
     * @param {Point} gPass 
     * @param {Point} gCMK
     * @param {boolean} rememberMe
     */
    async Convert(sessKey, gPass, gCMK, rememberMe){
        const clients = this.keyInfo.OrkInfo.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const voucherFlow = new VoucherFlow(this.keyInfo.OrkInfo.map(o => o.orkPaymentPublic), this.voucherURL, "signin");
        const {vouchers, k} = await voucherFlow.GetVouchers();

        const r1 = Math.RandomBigInt();
        const gBlurPass = gPass.mul(r1);

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map((client, i) => client.Convert(i, this.keyInfo.UserId, gBlurPass, sessKey.get_public_component(), rememberMe, vouchers.toORK(i), this.keyInfo.UserM, this.cmkCommitted, this.prismCommitted));
        
        // To save time
        const prkECDHi = await DH.generateECDHi(this.keyInfo.OrkInfo.map(o => o.orkPublic), sessKey.get_private_component().rawBytes);
        
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
                Point.fromBytes(Hex2Bytes(vouchers.qPub).slice(-32)), // to translate between tide component and native object
                BigIntFromByteArray(base64ToBytes(vouchers.UDeObf).slice(-32)), // to translate between tide component and native object
                k.get_private_component().priv,
                sessKey.get_public_component()
            )
        }
        return {
            VUID: this.cState.VUID
        }
    }
    /**
     * 
     * @param {TideKey} sessKey 
     * @param {Point} gSessKeyPub 
     * @param {Point} gPass 
     */
    async ConvertPassword(sessKey, gPass){
        if(this.cState != undefined) throw Error("This function must be called as a standlone in this flow");

        const r1 = RandomBigInt();
        const gBlurPass = gPass.mul(r1);

        const clients = this.keyInfo.OrkInfo.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const voucherFlow = new VoucherFlow(this.keyInfo.OrkInfo.map(o => o.orkPaymentPublic), this.voucherURL, "updateaccount");
        const {vouchers} = await voucherFlow.GetVouchers();

        const pre_convertPassResponses = clients.map((client, i) => client.ConvertPass(i, this.keyInfo.UserId, gBlurPass, sessKey.get_public_component(), vouchers.toORK(i), this.keyInfo.UserM));
        
        // To save time
        const prkECDHi = await DH.generateECDHi(this.keyInfo.OrkInfo.map(o => o.orkPublic), sessKey.get_private_component().rawBytes);
        
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
     * @param {Point} gVRK If a null value is provided, no encryption is applied.
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