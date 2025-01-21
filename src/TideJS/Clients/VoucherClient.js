import ClientBase from "./ClientBase.js";
import { Point } from "../../Cryptide/index.js";
import VoucherResponse from "../Models/Responses/Vendor/VoucherResponse.js";

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