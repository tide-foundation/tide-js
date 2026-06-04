// Copied from ork/Ork/Ork/Enclave/js/Flows/AuthenticationFlows/dCMKPasswordFlow.js at git 12e9f082 for tide-js load-harness v2.
// Patches:
//   1. Local imports re-rooted to the load-harness ork tree:
//      ../../Clients/NodeClient.js, ../../Math/KeyAuthentication.js.
//   2. ConvertPassword path uses `RandomBigInt` (from Cryptide.Math) and
//      our stubbed `ConvertPass` (off-path) — left as-is; calling it
//      raises a NodeClient stub error rather than running the flow.
//   3. Effective Threshold computed via `effectiveThreshold(OrkInfo)`
//      (i.e. `Math.min(Threshold, OrkInfo.length)`) for both Convert and
//      ConvertPassword WaitForNumberofORKs calls. This is the canonical
//      cohort-aware behaviour for any downstream consumer driving a flow
//      outside the per-deployment SWE bundling pipeline — `Threshold` /
//      `Max` in tide-js `Tools/Utils.ts` are upper-bound defaults
//      (14 / 20) and are patched per-deployment when the enclave bundle
//      is built (the production sork bundle ships `Threshold = 3,
//      Max = 5`, confirmed via minified symbols `const i=3,o=5` in
//      https://sork1.tideprotocol.com/bundle.f83c16e9c09d893485fe.js).
//      Each user's cohort is the `OrkInfo` it was bootstrapped with
//      (e.g. metrics-load-001 on staging has 5 ORKs at indices
//      1,5,7,8,10). The clamp is safe: it never asks for MORE than the
//      global default and never asks for MORE than the cohort actually
//      has — matching the deployed enclave semantics. See the comment
//      block above `Threshold` in tide-js `Tools/Utils.ts` for the full
//      rationale and the canonical `effectiveThreshold(orkInfo)` helper.
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

import { Cryptide, Tools, Models, Flow } from "@tideorg/js";

const DH = Cryptide.Encryption.DH;
const MathNS = Cryptide.Math;
const { effectiveThreshold, WaitForNumberofORKs, sortORKs } = Tools;
const { RandomBigInt } = Cryptide.Math;
const { BigIntFromByteArray, Hex2Bytes, base64ToBytes, serializeBitArray, bytesToBase64 } = Cryptide.Serialization;
const { Point } = Cryptide.Ed25519;
const TideKey = Cryptide.TideKey;
const KeyInfo = Models.Infos.KeyInfo;
const VoucherFlow = Flow.VoucherFlows.VoucherFlow;

import NodeClient from "../../Clients/NodeClient.js";
import { AuthenticateBasicReply, CmkConvertReply, PrismConvertReply } from "../../Math/KeyAuthentication.js";

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
     * @param {Cryptide.TideKey} sessKey
     * @param {Point} gPass
     * @param {Point} gCMK
     * @param {boolean} rememberMe
     * @param {Cryptide.TideKey|undefined} vendorSessionKey
     * @param {string|undefined} clientDPoPKey
     */
    async Convert(sessKey, gPass, gCMK, rememberMe, vendorSessionKey=null, clientDPoPKey=null){
        if(vendorSessionKey == null) vendorSessionKey = sessKey;
        const clients = this.keyInfo.OrkInfo.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const voucherFlow = new VoucherFlow(this.keyInfo.OrkInfo.map(o => o.orkPaymentPublic), this.voucherURL, "signin");
        const {vouchers, k} = await voucherFlow.GetVouchers();

        const r1 = MathNS.RandomBigInt();
        const gBlurPass = gPass.mul(r1);

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map((client, i) => client.Convert(i, this.keyInfo.UserId, gBlurPass, sessKey.get_public_component(), rememberMe, vouchers.toORK(i), this.keyInfo.UserM, this.cmkCommitted, this.prismCommitted));

        // To save time
        const prkECDHi = await DH.generateECDHi(this.keyInfo.OrkInfo.map(o => o.orkPublic), sessKey.get_private_component().rawBytes);

        const cohortThreshold = effectiveThreshold(this.keyInfo.OrkInfo);
        const {fulfilledResponses, bitwise} = await WaitForNumberofORKs(this.keyInfo.OrkInfo, pre_ConvertResponses, "CMK", cohortThreshold, null, prkECDHi);

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
                vendorSessionKey.get_public_component(),
                clientDPoPKey != null ? bytesToBase64(await vendorSessionKey.sign(new TextEncoder().encode("tide_sesskeyapproved_dpop_key:" + clientDPoPKey))) : null
            )
        }
        return {
            VUID: this.cState.VUID
        }
    }

    /**
     *
     * @param {TideKey} sessKey
     * @param {Point} gPass
     * NOTE (load-harness): not on the cmkOnly password-login path. Kept for
     * shape compatibility with the upstream ork file; calling it will throw
     * because the underlying NodeClient.ConvertPass is stubbed.
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

        const cohortThreshold = effectiveThreshold(this.keyInfo.OrkInfo);
        const { fulfilledResponses, bitwise } = await WaitForNumberofORKs(this.keyInfo.OrkInfo, pre_convertPassResponses, "CMK", cohortThreshold, null, prkECDHi);

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
     */
    async Authenticate(gVRK){
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
        return {
            bitwise: this.cState.bitwise,
            expired: this.cState.expired,
            selfRequesti: this.cState.selfRequesti,
            vendorEncryptedData: vendorEncryptedData
        }
    }
}
