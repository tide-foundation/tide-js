import Point from "../../../Cryptide/Ed25519.js";
import { prepVouchersReq } from "../../../Cryptide/Math.js";
import NodeClient from "../../Clients/NodeClient.js";
import VoucherClient from "../../Clients/VoucherClient.js";
import VoucherResponse from "../../Models/Responses/Vendor/VoucherResponse.js";
import { Max, Threshold, WaitForNumberofORKs } from "../../Tools/Utils.js";

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
        if(clientFunction == null){
            // get vouchers
            const {blurKeyPub, k} = await prepVouchersReq(this.orkPaymentPublics);
            const vendorClient = new VoucherClient(this.voucherURL);
            const vouchers = await vendorClient.GetVouchers(blurKeyPub, this.action, k.GetPublicKey());

            return {vouchers, k};
        }else{
            return this.GetVouchersWithAnotherClient(clientFunction);
        }
        
    }

    /**
     * I'm making this so I can use keycloak's client that has all of the keycloak's authorization built in.
     * @param {(request: string) => Promise<string>} clientFunction 
     * @returns 
     */
    async GetVouchersWithAnotherClient(clientFunction){
        // get vouchers
        const {blurKeyPub, k} = await prepVouchersReq(this.orkPaymentPublics);
        const request = JSON.stringify({
            BlurPORKi: blurKeyPub.map(blur => blur.toBase64()),
            ActionRequest: this.action,
            BlurerK: k.GetPublicKey().toBase64()
        });
        const response = await clientFunction(request);
        const vouchers = VoucherResponse.from(response, k.GetPublicKey().toBase64());
        return {vouchers, k};
    }
}