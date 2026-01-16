/**
 * @param {string|Uint8Array} message
 * @returns
 */
export declare function SHA256_Digest(message: any): Promise<Uint8Array<ArrayBuffer>>;
/**
 * @param {string|Uint8Array} message
 * @returns
 */
export declare function SHA512_Digest(message: any): Promise<Uint8Array<ArrayBuffer>>;
/**
 * DO NOT USE THIS TO SIGN. THE KEY IS THE HASH OF THE FIRST MESSAGE PASSED. THIS FUNCTION IS FOR HASHING MULTIPLE MESSAGES.
 * @param {string} message
 * @param {Point} pub
 */
export declare function HMAC_forHashing(message: any, pub: any): Promise<Uint8Array<ArrayBuffer>>;
