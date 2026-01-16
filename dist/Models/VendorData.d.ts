export default class VendorData {
    VUID: any;
    gCMKAuth: any;
    blindSig: any;
    AuthToken: any;
    /**
     *
     * @param {string} VUID
     * @param {Point} gCMKAuth
     * @param {string} blindSig
     * @param {AuthRequest} AuthToken
     */
    constructor(VUID: any, gCMKAuth: any, blindSig: any, AuthToken: any);
    toString(): string;
    static from(data: any): VendorData;
}
