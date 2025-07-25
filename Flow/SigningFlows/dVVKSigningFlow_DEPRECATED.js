import { EdDSA } from "../../Cryptide/index.js";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import { Max, Threshold, WaitForNumberofORKs, sortORKs } from "../../Tools/Utils.js";
import NodeClient from "../../Clients/NodeClient.js";
import OrkInfo from "../../Models/Infos/OrkInfo.js";
import { PreSign, Sign as SumS } from "../../Math/KeySigning.js";
import { BigIntToByteArray, ConcatUint8Arrays, bytesToBase64, serializeBitArray } from "../../Cryptide/Serialization.js";
import VoucherFlow from "../VoucherFlows/VoucherFlow.js";
import { Ed25519PublicComponent } from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";

export default class dVVKSigningFlow_DEPRECATED {
    /**
     * @param {string} vvkid
     * @param {Point} vvkPublic
     * @param {OrkInfo[]} orks 
     * @param {Uint8Array} sessKey 
     * @param {Point} gSessKey 
     * @param {string} voucherURL
     */
    constructor(vvkid, vvkPublic, orks, sessKey, gSessKey, voucherURL) {
        this.vvkid = vvkid;
        this.vvkPublic = vvkPublic;
        this.orks = orks;
        this.orks = sortORKs(this.orks); // sort for bitwise!

        this.sessKey = sessKey;
        this.gSessKey = gSessKey;
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
        const pre_clients = this.orks.map(info => new NodeClient(info.orkURL).AddBearerAuthorization(this.sessKey, new Ed25519PublicComponent(this.gSessKey).Serialize().ToString(), null).EnableTideDH(info.orkPublic));

        const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "vendorsign");
        const { vouchers } = await voucherFlow.GetVouchers(this.getVouchersFunction);

        const clients = await Promise.all(pre_clients); // to speed things up - computer shared key while grabbing vouchers

        const pre_PreSignResponses = clients.map((client, i) => client.PreSign(i, this.vvkid, request, vouchers.toORK(i)));
        const { fulfilledResponses, bitwise } = await WaitForNumberofORKs(this.orks, pre_PreSignResponses, "VVK", waitForAll ? Max : Threshold, null, clients);
        const GRj = PreSign(fulfilledResponses);

        const pre_SignResponses = clients.map(client => client.Sign(this.vvkid, request, GRj, serializeBitArray(bitwise)));
        const SignResponses = await Promise.all(pre_SignResponses);
        const Sj = SumS(SignResponses);

        if (GRj.length != Sj.length) throw Error("Weird amount of GRjs and Sjs");
        let sigs = [];
        for (let i = 0; i < GRj.length; i++) {
            sigs.push(ConcatUint8Arrays([GRj[i].toRawBytes(), BigIntToByteArray(Sj[i])]));
        }

        return sigs;
    }
}