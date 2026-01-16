/**
 *
 * @param {Point} gR
 * @param {Point} pub
 * @param {Uint8Array} message
 * @param {bigint} multiplier
 */
export declare function genBlindMessage(gR: any, pub: any, message: any, multiplier: any): Promise<{
    blurHCMKMul: bigint;
    blur: bigint;
    gRMul: any;
}>;
/**
 *
 * @param {bigint} blindS
 * @param {bigint} blur
 */
export declare function unblindSignature(blindS: any, blur: any): Promise<bigint>;
/**
 *
 * @param {bigint} S
 * @param {Point} noncePublic
 * @param {Point} pub
 * @param {Uint8Array} message
 */
export declare function verifyBlindSignature(S: any, noncePublic: any, pub: any, message: any): Promise<any>;
/**
 * @param {bigint} S
 * @param {Point} noncePublic
 */
export declare function serializeBlindSig(S: any, noncePublic: any): Uint8Array<any>;
