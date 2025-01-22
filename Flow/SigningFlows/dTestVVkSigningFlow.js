import { EdDSA } from "../../Cryptide/index.js";
import BaseTideRequest from "../../Models/BaseSignRequest.js";
import { Threshold, WaitForNumberofORKs, sortORKs } from "../../Tools/Utils.js";
import NodeClient from "../../Clients/NodeClient.js";
import OrkInfo from "../../Models/Infos/OrkInfo.js";
import { PreSign, Sign as SumS } from "../../Math/KeySigning.js";
import { BigIntToByteArray, ConcatUint8Arrays, StringToUint8Array, base64ToBytes, bytesToBase64, serializeBitArray } from "../../Cryptide/Serialization.js";
import VoucherFlow from "../VoucherFlows/VoucherFlow.js";
import { TestSignatureFormat } from "../Cryptide/Signing/TideSignature.js";

export default class dTestVVKSigningFlow{
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
    constructor(vvkid, vvkPublic, orks, sessKey, gSessKey, vrk, authorizer, authorizerCert, voucherURL){
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
        const proof = base64ToBytes(await EdDSA.sign(await request.dataToAuthorize(), this.vrk));
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
        const Sj = SumS(SignResponses);

        if(GRj.length != Sj.length) throw Error("Weird amount of GRjs and Sjs");
        const testSig = bytesToBase64(ConcatUint8Arrays([GRj[0].toArray(), BigIntToByteArray(Sj[0])]));

        const toVerify = "This msg was previously authorized <-mix-> New log in";
        const valid = await EdDSA.verify(testSig, this.vvkPublic, new TestSignatureFormat(toVerify).format());
        if(!valid) throw Error("Test VVK Signing failed");

        const endTime = performance.now();
        console.log(`Test VVK Signing took ${endTime - startTime} milliseconds.`);
    }
}