import { Max, sortORKs, Threshold, WaitForNumberofORKs } from "../../Tools/Utils.js";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import NodeClient from "../../Clients/NodeClient.js";
import VoucherFlow from "../VoucherFlows/VoucherFlow.js";
import { GetKeys } from "../../Math/KeyDecryption.js";
import { Doken } from "../../Models/Doken.js";
import { Ed25519PrivateComponent } from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import TideKey from "../../Cryptide/TideKey.js";

export default class dVVKDecryptionFlow{
    /**
     * @param {string} vvkid
     * @param {Point} vvkPublic
     * @param {OrkInfo[]} orks 
     * @param {TideKey} sessKey 
     * @param {Doken} doken 
     * @param {string} voucherURL
     */
    constructor(vvkid, vvkPublic, orks, sessKey, doken, voucherURL){
        this.vvkid = vvkid;
        this.vvkPublic = vvkPublic;
        this.orks = orks;
        this.orks = sortORKs(this.orks); // sort for bitwise!

        if(!doken.payload.sessionKey.Equals(sessKey.get_public_component())) throw Error("Mismatch between session key private and Doken session key public");
        this.sessKey = sessKey;
        this.doken = doken;
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
     * @param {BaseTideRequest} request 
     * @param {bool} waitForAll
     */
    async start(request, waitForAll=false){
        const pre_clients = this.orks.map(info => new NodeClient(info.orkURL).AddBearerAuthorization(this.sessKey.get_private_component().rawBytes, this.sessKey.get_public_component().Serialize().ToString(), this.doken.serialize()).EnableTideDH(info.orkPublic));
        
        const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "vendordecrypt");
        const {vouchers} = await voucherFlow.GetVouchers(this.getVouchersFunction);
        
        const clients = await Promise.all(pre_clients); // to speed things up - computer shared key while grabbing vouchers
        const pre_PreDecryptResponses = clients.map((client, i) => client.Decrypt(i, this.vvkid, request, vouchers.toORK(i)));
        const {fulfilledResponses, bitwise} = await WaitForNumberofORKs(this.orks, pre_PreDecryptResponses, "VVK", waitForAll ? Max : Threshold, null, clients);
        
        return GetKeys(fulfilledResponses, this.orks.map(o => BigInt(o.orkID))); // to be used for symmetric encryption now with caller
    }
}