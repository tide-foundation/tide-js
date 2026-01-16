import ClientBase from "./ClientBase";
export default class NodeClient extends ClientBase {
    enabledTideDH: boolean;
    DHKey: any;
    orkCacheId: any;
    /**
     * @param {string} url
     */
    constructor(url: any);
    isActive(): Promise<any>;
    /**
     * @param {Point} orkPublic
     */
    EnableTideDH(orkPublic: any): Promise<this>;
    /**
     * @param {number} index
     * @param {string} vuid
     * @param {BaseTideRequest} request
     * @param {string} voucher
     */
    PreSign(index: any, vuid: any, request: any, voucher: any): Promise<{
        index: any;
        data: {
            GRis: any[];
            AdditionalData: Uint8Array<ArrayBufferLike>;
        };
    }>;
    /**
     *
     * @param {string} vuid
     * @param {BaseTideRequest} request
     * @param {Point[]} GRs
     * @param {Uint8Array} bitwise
     * @param {Uint8Array} sessId
     */
    Sign(vuid: any, request: any, GRs: any, bitwise: any, sessId: any): Promise<{
        Sij: any[];
        AdditionalData: Uint8Array<ArrayBufferLike>;
    }>;
    /**
     * @param {number} index
     * @param {string} vuid
     * @param {BaseTideRequest} request
     * @param {string} voucher
     */
    Decrypt(index: any, vuid: any, request: any, voucher: any): Promise<{
        index: any;
        appliedC1s: any[];
    }>;
    /**
     * @param {number} i
     * @param {string} uid
     * @param {Point} gSessKeyPub
     * @param {bigint} channelId
     * @param {string} homeOrkUrl
     * @param {string} voucher
     */
    RecoverAccount(i: any, uid: any, gSessKeyPub: any, channelId: any, homeOrkUrl: any, voucher: any): Promise<{
        index: any;
        responseData: any;
    }>;
    FinalizeAccountRecovery(uid: any, channelId: any): Promise<{
        responseData: any;
    }>;
    CreateCheckoutSession(vendorData: any, redirectUrl: any, licensingTier: any): Promise<Response>;
    IsLicenseActive(vendorId: any): Promise<boolean>;
    GetLicenseDetails(vendorId: any, timestamp: any, timestampSig: any): Promise<any>;
    GetSubscriptionStatus(vendorId: any, initialSessionId: any, timestamp: any, timestampSig: any): Promise<any>;
    CreateCustomerPortalSession(vendorId: any, redirectUrl: any, timestamp: any, timestampSig: any): Promise<any>;
    UpdateSubscription(updateRequest: any, licenseId: any, timestamp: any, timestampSig: any): Promise<any>;
    CancelSubscription(licenseId: any, initialSessionId: any, timestamp: any, timestampSig: any): Promise<any>;
}
