export declare class TideSignatureFormat {
    Name: any;
    Version: any;
    Header: () => string;
    Footer: () => string;
    /**
     * @param {string|Uint8Array} message
     */
    constructor(message: any);
    /**
     *
     * @returns {Uint8Array}
     */
    format(): Uint8Array<any>;
}
export declare class PolicyAuthorizedTideRequestSignatureFormat extends TideSignatureFormat {
    Name: string;
    Version: string;
    constructor(issueTimeBytes: any, exp: any, modelId: any, draftHash: any);
}
export declare class URLSignatureFormat extends TideSignatureFormat {
    Name: string;
    Version: string;
    constructor(message: any);
}
export declare class ClientURLSignatureFormat extends TideSignatureFormat {
    Name: string;
    Version: string;
    constructor(message: any);
}
export declare class PublicKeySignatureFormat extends TideSignatureFormat {
    Name: string;
    Version: string;
    constructor(message: any);
}
export declare class AuthorizerSignatureFormat extends TideSignatureFormat {
    Name: string;
    Version: string;
    constructor(authflow: any, modelIds: any, authorizer: any);
    format(): any;
}
export declare class TidecloakSettingsSignatureFormat extends TideSignatureFormat {
    Name: string;
    Version: string;
    constructor(message: any);
}
export declare class TestSignatureFormat extends TideSignatureFormat {
    Name: string;
    Version: string;
    constructor(message: any);
}
export declare class PlainSignatureFormat extends TideSignatureFormat {
    /**
     * WARNING: Only use this class if you are SURE that the data you are signing is ALREADY serialized in some form.
     * @param {string|Uint8Array} message
     */
    constructor(message: any);
    format(): any;
}
