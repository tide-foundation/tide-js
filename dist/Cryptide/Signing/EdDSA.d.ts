/**
 * Sign the msg with a private key in non-standard way as it uses a random number generator. Non-deterministic.
 * @param {string | Uint8Array} msg
 * @param {bigint} priv
 * @returns A base64 encoding of the signature
 */
export declare function sign(msg: any, priv: any): Promise<string>;
/**
 * Verify a EdDSA signature, given a signature, public key and message.
 * @param {string} sig In base64
 * @param {string | Point} pub
 * @param {string | Uint8Array} msg
 * @returns Boolean dependant on whether the signature is valid or not.
 */
export declare function verify(sig: any, pub: any, msg: any): Promise<any>;
/**
 * Verify a message with raw S and R
 * @param {bigint} S
 * @param {Point} R
 * @param {Point} A
 * @param {Uint8Array} M
 */
export declare function verifyRaw(S: any, R: any, A: any, M: any): Promise<any>;
