export declare class ModelRegistry {
    /**
     * @returns {HumanReadableModelBuilder}
     */
    static getHumanReadableModelBuilder(reqId: any, data: any): CustomSignRequestBuilder | HumanReadableModelBuilder;
}
export declare class HumanReadableModelBuilder {
    _humanReadableName: any;
    constructor(data: any, reqId: any);
    static create(data: any, reqId: any): HumanReadableModelBuilder;
    getDetailsMap(): any[];
    getRequestDataJson(): {};
    getExpiry(): any;
    getDataToApprove(): Promise<any>;
}
declare class CustomSignRequestBuilder extends HumanReadableModelBuilder {
    get _id(): string;
    constructor(data: any, reqId: any);
    getRequestDataJson(): any;
}
export declare class OffboardSignRequestBuilder extends HumanReadableModelBuilder {
    _name: string;
    _version: string;
    _humanReadableName: string;
    get _id(): string;
    constructor(data: any, reqId: any);
    getDetailsMap(): {};
    getRequestDataJson(): {
        "Vendor Rotating Key for Offboarding": any;
    };
}
export {};
