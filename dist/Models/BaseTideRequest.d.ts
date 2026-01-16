export default class BaseTideRequest {
    /**
     *
     * @param {string} name
     * @param {string} version
     * @param {string} authFlow
     * @param {Uint8Array} draft
     * @param {Uint8Array} dyanmicData
     */
    constructor(name: any, version: any, authFlow: any, draft: any, dyanmicData?: Uint8Array<ArrayBuffer>);
    id(): string;
    /**
     * This isn't copying. Just created another BaseTideRequest object that allows you to point each individual field to OTHER sections of memory.
     * If you modify an existing 'replicated' field, you'll also modify the other object you originally replicated.
     */
    replicate(): BaseTideRequest;
    /**
     * @param {Uint8Array} d
     */
    setNewDynamicData(d: any): this;
    /**
     *
     * @param {number} timeFromNowInSeconds
     */
    setCustomExpiry(timeFromNowInSeconds: any): this;
    /**
     * @param {Uint8Array} authorizer
     */
    addAuthorizer(authorizer: any): void;
    /**
     *
     * @param {Uint8Array} authorizerCertificate
     */
    addAuthorizerCertificate(authorizerCertificate: any): void;
    /**
     *
     * @param {Uint8Array} authorization
     */
    addAuthorization(authorization: any): this;
    dataToAuthorize(): Promise<Uint8Array<ArrayBuffer>>;
    getInitializedTime(): bigint;
    /**
     * Add an approval for this request. To be used for policy auth flow
     * @param {Doken} doken
     * @param {Uint8Array} sig
     */
    addApproval(doken: any, sig: any): void;
    encode(): Uint8Array<any>;
    static decode(data: any): BaseTideRequest;
    dataToApprove(): Promise<Uint8Array<any>>;
}
