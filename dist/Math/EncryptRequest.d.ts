export default class EncryptRequest {
    /**
     *
     * @param {Point} gCVK
     * @param {Uint8Array} fieldDatum
     * @param {number} timestamp
     */
    static generatePartialRequest(gCVK: any, fieldDatum: any, timestamp: any): Promise<{
        C1: any;
        EncField: Uint8Array<any>;
        EncFieldChk: Uint8Array<ArrayBuffer>;
        timestamp: any;
    }>;
    /**
     * @param {{
            C1: Point;
            EncField: Uint8Array;
            EncFieldChk: Uint8Array;
            timestamp: number;
        }[]} partialRequests
     * @param {bigint} li
     * @param {Datum[]} datums
     * @param {Point[]} gCVKRi
     * @param {Uint8Array} ECDHi
     */
    static generateEncryptedRequest(partialRequests: any, li: any, datums: any, gCVKRi: any, ECDHi: any): Promise<string>;
    /**
     * Will decrypt encrypted sigs, validate those sigs, and generate the serialized fields for the vendor to store
     * @param {string[]} encryptedS
     * @param  {{
            EncFields: Uint8Array[];
            EncFieldChks: Uint8Array[];
            C1s: Point[];
            Tags: number[];
            GCVKRi: Point[];
            Timestamp: number;
        }} plainRequest
     * @param {bigint[]} lis
     * @param {Uint8Array[]} ECDHi
     * @param {Point} gCVK
     */
    static generateSerializedFields(encryptedS: any, plainRequest: any, lis: any, ECDHi: any, gCVK: any): Promise<any>;
}
