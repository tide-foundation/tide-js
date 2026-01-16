/**
 * @param {bigint} a
 * @param {bigint} b
 * @returns {bigint}
 */
export declare function mod(a: any, b?: bigint): bigint;
/**
 *
 * @param {bigint[]} numbers
 * @returns
 */
export declare function median(numbers: any): unknown;
/**
 * @returns {bigint}
 */
export declare function RandomBigInt(): bigint;
export declare function GenSessKey(): Uint8Array<any>;
/**
 * @param {Point} gPassPRISM
 * @returns
 */
export declare function CreateGPrismAuth(gPassPRISM: any): Promise<any>;
/**
 *
 * @param {bigint | Uint8Array} a
 */
export declare function GetPublic(a: any): any;
/**
 *
 * @param {number[]} arr
 * @returns
 */
export declare function Min(arr: any): any;
/**
 * @param {bigint} number
 * @param {bigint} modulo
 * @returns {bigint}
 */
export declare function mod_inv(number: any, modulo?: bigint): bigint;
/**
*
* @param {Point[]} points
*/
export declare function SumPoints(points: any): any;
