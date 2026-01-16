export default class ElGamal {
    /**
     *
     * @param {Uint8Array} secretData
     * @param {Point} publicKey
     */
    static encryptData(secretData: any, publicKey: any): Promise<string>;
    /**
     *
     * @param {Uint8Array} secretData
     * @param {Point} publicKey
     */
    static encryptDataRaw(secretData: any, publicKey: any): Promise<Uint8Array<any>>;
    /**
     * @param {string} base64_c1_c2
     * @param {bigint | Uint8Array} k
     */
    static decryptData(base64_c1_c2: any, k: any): Promise<Uint8Array<ArrayBuffer>>;
    /**
     * @param {Uint8Array} base64_c1_c2
     * @param {bigint | Uint8Array} k
     */
    static decryptDataRaw(base64_c1_c2: any, k: any): Promise<Uint8Array<ArrayBuffer>>;
}
