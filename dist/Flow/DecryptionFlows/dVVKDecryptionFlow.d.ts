export default class dVVKDecryptionFlow {
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
    /**
     * @param {BaseTideRequest} request
     * @param {bool} waitForAll
     */
    start(request: any, waitForAll?: boolean): Promise<any[]>;
}
