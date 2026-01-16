/**
 * @param {Point} pub
 * @param {BigInt|string|Uint8Array} priv
 */
export declare function computeSharedKey(pub: any, priv: any): Promise<Uint8Array<ArrayBuffer>>;
/**
 *
 * @param {Point[]} pubs
 * @param {bigint|string|Uint8Array} priv
 */
export declare function generateECDHi(pubs: any, priv: any): Promise<any[]>;
