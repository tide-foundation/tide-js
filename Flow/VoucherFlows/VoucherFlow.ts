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
import { Point } from "../../Cryptide/Ed25519";
import VoucherClient from "../../Clients/VoucherClient";
import VoucherResponse from "../../Models/Responses/Vendor/VoucherResponse";
import TideKey from "../../Cryptide/TideKey";
import Ed25519Scheme from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme";

export default class VoucherFlow{
    orkPaymentPublics: any;
    voucherURL: any;
    action: any;
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
        const k = TideKey.NewKey(Ed25519Scheme);
        const blurKeyPub = await k.prepVouchersReq(this.orkPaymentPublics);
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