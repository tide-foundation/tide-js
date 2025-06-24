import { Max, sortORKs, Threshold, WaitForNumberofORKs } from "../../Tools/Utils.js";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import NodeClient from "../../Clients/NodeClient.js";
import VoucherFlow from "../VoucherFlows/VoucherFlow.js";
import { GetKeys } from "../../Math/KeyDecryption.js";

export default class dVVKDecryptionFlow{
    /**
     * @param {string} vvkid
     * @param {Point} vvkPublic
     * @param {OrkInfo[]} orks 
     * @param {Uint8Array} sessKey 
     * @param {Point} gSessKey 
     * @param {string} voucherURL
     */
    constructor(vvkid, vvkPublic, orks, sessKey, gSessKey, voucherURL){
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
    setVoucherRetrievalFunction(getVouchersFunction){
        this.getVouchersFunction = getVouchersFunction;
        return this;
    }
    /**
     * 
     * @param {string} doken 
     */
    setDoken(doken){
        this.doken = doken;
    }
    /**
     * @param {BaseTideRequest} request 
     * @param {bool} waitForAll
     */
    async start(request, waitForAll=false){
        const pre_clients = this.orks.map(info => new NodeClient(info.orkURL).AddBearerAuthorization(this.doken).EnableTideDH(this.gSessKey, this.sessKey, info.orkPublic));
        
        const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "vendordecrypt");
        const {vouchers} = await voucherFlow.GetVouchers(this.getVouchersFunction);
        
        const clients = await Promise.all(pre_clients); // to speed things up - computer shared key while grabbing vouchers
        const pre_PreDecryptResponses = clients.map((client, i) => client.Decrypt(i, this.vvkid, request, vouchers.toORK(i)));
        const {fulfilledResponses, bitwise} = await WaitForNumberofORKs(this.orks, pre_PreDecryptResponses, "VVK", waitForAll ? Max : Threshold, null, clients);
        
        return GetKeys(fulfilledResponses, this.orks.map(o => BigInt(o.orkID))); // to be used for symmetric encryption now with caller
    }
}