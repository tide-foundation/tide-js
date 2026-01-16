export default class dTestVVKSigningFlow {
    /**
     * @param {string} vvkid
     * @param {Point} vvkPublic
     * @param {OrkInfo[]} orks
     * @param {Uint8Array} sessKey
     * @param {Point} gSessKey
     * @param {BigInt} vrk
     * @param {Uint8Array} authorizer
     * @param {Uint8Array} authorizerCert
     * @param {string} voucherURL
     */
    constructor(vvkid: any, vvkPublic: any, orks: any, sessKey: any, gSessKey: any, vrk: any, authorizer: any, authorizerCert: any, voucherURL: any);
    start(): Promise<void>;
}
