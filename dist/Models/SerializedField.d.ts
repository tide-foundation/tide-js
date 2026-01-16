export default class SerializedField {
    static version: number;
    /**
     *
     * @param {Uint8Array} encData
     * @param {number} timestamp
     * @param {Uint8Array} encKey
     * @param {Uint8Array} signature
     */
    static create(encData: any, timestamp: any, encKey?: any, signature?: any): Uint8Array<any>;
    /**
     * @param {Uint8Array} serializedField
     */
    static deserialize(serializedField: any): {
        encFieldChk: Uint8Array<ArrayBufferLike>;
        timestamp: Uint8Array<ArrayBufferLike>;
        encKey: Uint8Array<ArrayBufferLike>;
        signature: Uint8Array<ArrayBufferLike>;
    };
}
