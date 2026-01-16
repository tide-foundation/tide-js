/**
 *
 * @param {Uint8Array} rawKey
 * @param {Iterable} keyUsage
 * @returns
 */
export declare function createAESKey(rawKey: any, keyUsage: any): Promise<CryptoKey>;
/**
 * @param {string|Uint8Array} secretData
 * @param {Uint8Array|bigint|string} key
 * @returns
 */
export declare function encryptData(secretData: any, key: any): Promise<string>;
/**
 * @param {Uint8Array} encodedData
 * @param {Uint8Array} aesKey
 * @returns
 */
export declare function encryptDataRawOutput(encodedData: any, aesKey: any): Promise<Uint8Array<any>>;
/**
 * @param {string} encryptedData
 * @param {Uint8Array|bigint|string} key
 * @returns
 */
export declare function decryptData(encryptedData: any, key: any): Promise<string>;
/**
 * @param {Uint8Array} encryptedData
 * @param {Uint8Array} key 32 bytes
 */
export declare function decryptDataRawOutput(encryptedData: any, key: any): Promise<Uint8Array<ArrayBuffer>>;
