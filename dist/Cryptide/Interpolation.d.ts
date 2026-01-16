/**
 * @param {bigint} xi
 * @param {bigint[]} xs
 * @param {bigint} m
 * @returns {bigint}
 */
export declare function GetLi(xi: any, xs: any, m?: bigint): any;
/**
 * @param {bigint[]} ids
 */
export declare function GetLis(ids: any): any;
/**
 *
 * @param {Point[]} points
 */
export declare function AggregatePoints(points: any): any;
/**
 *
 * @param {Ed25519PublicComponent[]} points
 */
export declare function AggregatePublicComponents(points: any): any;
/**
 *
 * @param {Ed25519PublicComponent[]} pointArrays
 */
export declare function AggregatePublicComponentArrays(pointArrays: any): any;
/**
 * Will aggregate all points at corresponding indexes. E.g. all points from each array at index 0 will be summed.
 * @param {Point[][]} pointArrays
 */
export declare function AggregatePointArrays(pointArrays: any): any;
/**
 * Will aggregate all points and multiply by corresponding li of id.
 * @param {Point[]} points
 * @param {bigint[]} ids
 * @returns {Point}
 */
export declare function AggregatePointsWithIds(points: any, ids: any): any;
/**
 * Will aggregate all points and multiply by corresponding li.
 * @param {Point[]} points
 * @param {bigint[]} lis
 * @returns {Point}
 */
export declare function AggregatePointsWithLis(points: any, lis: any): any;
