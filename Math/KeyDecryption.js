import { SHA256_Digest } from "../Cryptide/Hashing/Hash.js";
import { Point } from "../Cryptide/index.js";
import { AggregatePointArrays, GetLis } from "../Cryptide/Interpolation.js";

/**
 * 
 * @param {Point[][]} appliedC1s 
 * @param {bigint[]} ids 
 */
export async function GetKeys(appliedC1s, ids){
    // Apply Lis to points, sum result
    const lis = GetLis(ids);
    const appliedC1sWithLi = appliedC1s.map((c1, i) => c1.map(c => c.times(lis[i])));
    return Promise.all(AggregatePointArrays(appliedC1sWithLi).map(async p => SHA256_Digest(p.toArray())));
}