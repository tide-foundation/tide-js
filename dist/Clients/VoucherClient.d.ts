import ClientBase from "./ClientBase";
import VoucherResponse from "../Models/Responses/Vendor/VoucherResponse";
export default class VoucherClient extends ClientBase {
    /**
     * @param {string} url
     */
    constructor(url: any);
    /**
     *
     * @param {Point[]} blurPORKi
     * @param {string} actionRequest
     * @param {Point} blurerK
     */
    GetVouchers(blurPORKi: any, actionRequest: any, blurerK: any): Promise<VoucherResponse>;
}
