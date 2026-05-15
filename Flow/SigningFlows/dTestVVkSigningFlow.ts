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

import { Signing } from "../../Cryptide/index";
import BaseTideRequest from "../../Models/BaseTideRequest";
import { Threshold, WaitForNumberofORKs, sortORKs } from "../../Tools/Utils";
import NodeClient from "../../Clients/NodeClient";
import OrkInfo from "../../Models/Infos/OrkInfo";
import { PreSign, Sign as SumS } from "../../Math/KeySigning";
import { BigIntToByteArray, ConcatUint8Arrays, StringToUint8Array, base64ToBytes, bytesToBase64, serializeBitArray } from "../../Cryptide/Serialization";
import VoucherFlow from "../VoucherFlows/VoucherFlow";
import { TestSignatureFormat } from "../../Cryptide/Signing/TideSignature";
import { TideError } from "../../Errors/TideError";
import { TideJsErrorCodes } from "../../Errors/codes";

export default class dTestVVKSigningFlow{
    vvkid: string;
    vvkPublic: any;
    orks: OrkInfo[];
    sessKey: Uint8Array;
    gSessKey: any;
    vrk: bigint;
    authorizer: Uint8Array;
    authorizerCert: Uint8Array;
    voucherURL: string;

    constructor(vvkid: string, vvkPublic: any, orks: OrkInfo[], sessKey: Uint8Array, gSessKey: any, vrk: bigint, authorizer: Uint8Array, authorizerCert: Uint8Array, voucherURL: string){
        this.vvkid = vvkid;
        this.vvkPublic = vvkPublic;
        this.orks = orks;
        this.orks = sortORKs(this.orks); // sort for bitwise!

        this.sessKey = sessKey;
        this.gSessKey = gSessKey;
        this.vrk = vrk;
        this.authorizer = authorizer;
        this.authorizerCert = authorizerCert;
        this.voucherURL = voucherURL;
    }
    async start(){
        const startTime = performance.now();

        const draft = `{"SomeStaticData":"This msg was previously authorized"}`;
        const dynamicData = `{"SomeDynamicData":"New log in"}`;
        const request = new BaseTideRequest("TestInit", "1", "VRK:1", StringToUint8Array(draft), StringToUint8Array(dynamicData));
        const proof = base64ToBytes(await Signing.EdDSA.sign(await request.dataToAuthorize(), this.vrk));
        var x = await request.dataToAuthorize();
        request.addAuthorization(proof);
        request.addAuthorizer(this.authorizer);
        request.addAuthorizerCertificate(this.authorizerCert);


        const clients = await Promise.all(this.orks.map(async info => await new NodeClient(info.orkURL).EnableTideDH(this.gSessKey, this.sessKey, info.orkPublic)));

        const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "vendorsign");
        const {vouchers} = await voucherFlow.GetVouchers();

        const pre_PreSignResponses = clients.map((client, i) => client.PreSign(i, this.vvkid, request, vouchers.toORK(i)));
        const {fulfilledResponses, bitwise} = await WaitForNumberofORKs(this.orks, pre_PreSignResponses, "VVK", Threshold, null, clients);
        const GRj = PreSign(fulfilledResponses);

        const pre_SignResponses = clients.map(client => client.Sign(this.vvkid, request, GRj, serializeBitArray(bitwise)));
        const SignResponses = await Promise.all(pre_SignResponses);
        const Sj = SumS(SignResponses.map(s => s.Sij));

        if(GRj.length != Sj.length) throw new TideError({
            code: TideJsErrorCodes.CRYPTO_GRJ_SJ_LENGTH_MISMATCH,
            displayMessage: `GRj/Sj length mismatch: GRjs=${GRj.length}, Sjs=${Sj.length}, vvkid=${String(this.vvkid).slice(0, 12)}`,
            source: "Flow/SigningFlows/dTestVVkSigningFlow.ts:78",
        });
        const testSig = bytesToBase64(ConcatUint8Arrays([GRj[0].toRawBytes(), BigIntToByteArray(Sj[0])]));

        const toVerify = "This msg was previously authorized <-mix-> New log in";
        const valid = await Signing.EdDSA.verify(testSig, this.vvkPublic, new TestSignatureFormat(toVerify).format());
        if(!valid) throw new TideError({
            code: TideJsErrorCodes.SIG_BLIND_VERIFY_FAILED,
            displayMessage: "Test VVK signing self-check could not be verified. Please try again. If the problem persists, contact support.",
            source: "Flow/SigningFlows/dTestVVkSigningFlow.ts:89",
            details: [
                {
                    displayMessage: "EdDSA.verify returned false for the assembled test signature",
                    code: `vvkid=${String(this.vvkid).slice(0, 12)} testSig=${testSig.slice(0, 16)}... toVerify="${toVerify}"`,
                },
            ],
        });

        const endTime = performance.now();
        console.log(`Test VVK Signing took ${endTime - startTime} milliseconds.`);
    }
}