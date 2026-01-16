export default class OrkInfo {
    orkID: any;
    orkPublic: any;
    orkURL: any;
    orkPaymentPublic: any;
    /**
     *
     * @param {string} orkID
     * @param {Point} orkPublic
     * @param {string} orkURL
     * @param {Point} orkPaymentPublic
     */
    constructor(orkID: any, orkPublic: any, orkURL: any, orkPaymentPublic: any);
    toString(): string;
    toNativeTypeObject(): {
        Id: any;
        PublicKey: any;
        URL: any;
        PaymentPublicKey: any;
    };
    static fromNativeTypeObject(json: any): OrkInfo;
    static from(json: any): OrkInfo;
}
