export default class AuthRequest {
    /**
     *
     * @param {string} keyId
     * @param {string} purpose
     * @param {string} keyPub
     * @param {bigint} expiry
     * @param {string} sessionId
     */
    constructor(keyId: any, purpose: any, keyPub: any, expiry: any, sessionId?: any);
    toUint8Array(): Uint8Array<ArrayBuffer>;
    toString(): string;
    /**
     * @param {string} keyId
     * @param {string} purpose
     * @param {string} clientKey
     * @param {bigint} expiry
     * @param {string} sessionId
     * @returns
     */
    static new(keyId: any, purpose: any, clientKey: any, expiry: any, sessionId?: any): AuthRequest;
    static from(data: any): AuthRequest;
}
