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

import ClientBase from "./ClientBase.js";
import VoucherResponse from "../Models/Responses/Vendor/VoucherResponse.js";
import { Point } from "../Cryptide/Ed25519.js";

export default class VoucherClient extends ClientBase{
    /**
     * @param {string} url 
     */
    constructor(url){
        super(url);
    }

    /**
     * 
     * @param {Point[]} blurPORKi 
     * @param {string} actionRequest 
     * @param {Point} blurerK 
     */
    async GetVouchers(blurPORKi, actionRequest, blurerK){
        const request = JSON.stringify({
            BlurPORKi: blurPORKi.map(blur => blur.toBase64()),
            ActionRequest: actionRequest,
            BlurerK: blurerK.toBase64()
        });

        const data = this._createFormData({
            'voucherRequest': request
        });

        const response = await this._post(``, data);
        const respondeData = await this._handleError(response, "Get Vouchers", true);

        return VoucherResponse.from(respondeData, blurerK.toBase64());
    }
}