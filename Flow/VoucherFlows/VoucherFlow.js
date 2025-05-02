import { Point } from "../../Cryptide/Ed25519.js";
import NodeClient from "../../Clients/NodeClient.js";
import VoucherClient from "../../Clients/VoucherClient.js";
import VoucherResponse from "../../Models/Responses/Vendor/VoucherResponse.js";
import { Max, Threshold, WaitForNumberofORKs } from "../../Tools/Utils.js";
import TideKey from "../../Cryptide/TideKey.js";
import Ed25519Scheme from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js";

export default class VoucherFlow{
    
    /**
     * @param {Point[]} orkPaymentPublics
     * @param {string} voucherURL 
     * @param {string} action
     */
    constructor(orkPaymentPublics, voucherURL, action){
        this.orkPaymentPublics = orkPaymentPublics;
        this.voucherURL = voucherURL;
        this.action = action;
    }
    /**
     * I'm making this so I can use keycloak's client that has all of the keycloak's authorization built in.
     * @param {(request: string) => Promise<string>} clientFunction 
     * @returns 
     */
    async GetVouchers(clientFunction = null){
        let vouchers = undefined;
        const k = await TideKey.NewKey(Ed25519Scheme);
        const blurKeyPub = k.prepVouchersReq(this.orkPaymentPublics);
        if(clientFunction == null){
            // get vouchers
            const vendorClient = new VoucherClient(this.voucherURL);
            vouchers = await vendorClient.GetVouchers(blurKeyPub, this.action, k.get_public_component().public);
        }else{
            const request = JSON.stringify({
                BlurPORKi: blurKeyPub.map(blur => blur.toBase64()),
                ActionRequest: this.action,
                BlurerK: k.get_public_component().public.toBase64()
            });
            const response = await clientFunction(request);
            vouchers = VoucherResponse.from(response, k.get_public_component().public.toBase64());
        }
        return {vouchers, k}
    }
}