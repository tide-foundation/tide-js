export default class DecryptRequest {
    /**
     *
     * @param {Uint8Array[]} serializedFields
     * @param {Uint8Array[]} ECDHi
     */
    static generateRequests(serializedFields: any, ECDHi: any): Promise<{
        encRequests: any[];
        encryptedFields: any;
        tags: any;
    }>;
    /**
     * @param {Uint8Array[]} encryptedFields
     * @param {Uint8Array[]} ECDHi
     * @param {string[]} encryptedFieldKeys
     * @param {bignt[]} lis
     */
    static decryptFields(encryptedFields: any, ECDHi: any, encryptedFieldKeys: any, lis: any): Promise<any[]>;
}
