export default class VoucherResponse {
    voucherPacks: any;
    qPub: any;
    payerPub: any;
    Yhat: any;
    blurerK: any;
    UDeObf: any;
    /**
     *
     * @param {string[]} voucherPacks
     * @param {string} qPub
     * @param {string} payerPub
     * @param {string} YHat
     * @param {string} blurerK
     * @param {string} UDeObf
     */
    constructor(voucherPacks: any, qPub: any, payerPub: any, Yhat: any, blurerK: any, UDeObf: any);
    static from(data: any, blurerK: any): VoucherResponse;
    /**
     *
     * @param {number} index
     * @returns
     */
    toORK(index: any): string;
}
