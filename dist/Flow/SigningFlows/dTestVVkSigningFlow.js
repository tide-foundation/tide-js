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
const index_1 = require("../../Cryptide/index");
const BaseTideRequest_1 = __importDefault(require("../../Models/BaseTideRequest"));
const Utils_1 = require("../../Tools/Utils");
const NodeClient_1 = __importDefault(require("../../Clients/NodeClient"));
const KeySigning_1 = require("../../Math/KeySigning");
const Serialization_1 = require("../../Cryptide/Serialization");
const VoucherFlow_1 = __importDefault(require("../VoucherFlows/VoucherFlow"));
const TideSignature_1 = require("../../Cryptide/Signing/TideSignature");
class dTestVVKSigningFlow {
    /**
     * @param {string} vvkid
     * @param {Point} vvkPublic
     * @param {OrkInfo[]} orks
     * @param {Uint8Array} sessKey
     * @param {Point} gSessKey
     * @param {BigInt} vrk
     * @param {Uint8Array} authorizer
     * @param {Uint8Array} authorizerCert
     * @param {string} voucherURL
     */
    constructor(vvkid, vvkPublic, orks, sessKey, gSessKey, vrk, authorizer, authorizerCert, voucherURL) {
        this.vvkid = vvkid;
        this.vvkPublic = vvkPublic;
        this.orks = orks;
        this.orks = (0, Utils_1.sortORKs)(this.orks); // sort for bitwise!
        this.sessKey = sessKey;
        this.gSessKey = gSessKey;
        this.vrk = vrk;
        this.authorizer = authorizer;
        this.authorizerCert = authorizerCert;
        this.voucherURL = voucherURL;
    }
    async start() {
        const startTime = performance.now();
        const draft = `{"SomeStaticData":"This msg was previously authorized"}`;
        const dynamicData = `{"SomeDynamicData":"New log in"}`;
        const request = new BaseTideRequest_1.default("TestInit", "1", "VRK:1", (0, Serialization_1.StringToUint8Array)(draft), (0, Serialization_1.StringToUint8Array)(dynamicData));
        const proof = (0, Serialization_1.base64ToBytes)(await index_1.EdDSA.sign(await request.dataToAuthorize(), this.vrk));
        var x = await request.dataToAuthorize();
        request.addAuthorization(proof);
        request.addAuthorizer(this.authorizer);
        request.addAuthorizerCertificate(this.authorizerCert);
        const clients = await Promise.all(this.orks.map(async (info) => await new NodeClient_1.default(info.orkURL).EnableTideDH(this.gSessKey, this.sessKey, info.orkPublic)));
        const voucherFlow = new VoucherFlow_1.default(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "vendorsign");
        const { vouchers } = await voucherFlow.GetVouchers();
        const pre_PreSignResponses = clients.map((client, i) => client.PreSign(i, this.vvkid, request, vouchers.toORK(i)));
        const { fulfilledResponses, bitwise } = await (0, Utils_1.WaitForNumberofORKs)(this.orks, pre_PreSignResponses, "VVK", Utils_1.Threshold, null, clients);
        const GRj = (0, KeySigning_1.PreSign)(fulfilledResponses);
        const pre_SignResponses = clients.map(client => client.Sign(this.vvkid, request, GRj, (0, Serialization_1.serializeBitArray)(bitwise)));
        const SignResponses = await Promise.all(pre_SignResponses);
        const Sj = (0, KeySigning_1.Sign)(SignResponses);
        if (GRj.length != Sj.length)
            throw Error("Weird amount of GRjs and Sjs");
        const testSig = (0, Serialization_1.bytesToBase64)((0, Serialization_1.ConcatUint8Arrays)([GRj[0].toRawBytes(), (0, Serialization_1.BigIntToByteArray)(Sj[0])]));
        const toVerify = "This msg was previously authorized <-mix-> New log in";
        const valid = await index_1.EdDSA.verify(testSig, this.vvkPublic, new TideSignature_1.TestSignatureFormat(toVerify).format());
        if (!valid)
            throw Error("Test VVK Signing failed");
        const endTime = performance.now();
        console.log(`Test VVK Signing took ${endTime - startTime} milliseconds.`);
    }
}
exports.default = dTestVVKSigningFlow;
