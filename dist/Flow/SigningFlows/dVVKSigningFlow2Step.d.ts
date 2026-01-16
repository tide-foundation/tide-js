export default class dVVKSigningFlow2Step {
    /**
     * @param {string} vvkid
     * @param {Point} vvkPublic
     * @param {OrkInfo[]} orks
     * @param {TideKey} sessKey
     * @param {Doken} doken
     * @param {string} voucherURL
     */
    constructor(vvkid: any, vvkPublic: any, orks: any, sessKey: any, doken: any, voucherURL: any);
    /**
     * @param {(request: string) => Promise<string> } getVouchersFunction
     * @returns {dVVKSigningFlow}
     */
    setVoucherRetrievalFunction(getVouchersFunction: any): this;
    setRequest(request: any): Promise<void>;
    overrideVoucherAction(action: any): Promise<void>;
    getVouchers(): any;
    /**
     *
     * @param {Uint8Array | Uint8Array[]} dynamicData
     * @returns {Promise<Uint8Array[]>}
     */
    preSign(dynamicData: any): Promise<any[]>;
    /**
     * @param {Uint8Array | Uint8Array[]} dynamicData
     * @returns
     */
    sign(dynamicData: any): Promise<{
        sigs: any[];
        addionalDatas: any;
    }>;
}
