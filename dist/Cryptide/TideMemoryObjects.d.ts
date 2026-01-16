/**
 *
 * @param {Ed25519PublicComponent} gvrk
 * @param {number | bigint} expiry
 */
export declare function CreateVRKPackage(gvrk: any, expiry: any): Uint8Array<any>;
/**
 *
 * @param {string} authFlow
 * @param {string[]} signModels
 * @param {Uint8Array} vrk_pack
 * @returns
 */
export declare function CreateAuthorizerPackage(authFlow: any, signModels: any, vrk_pack: any): any;
