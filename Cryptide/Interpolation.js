// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

import { mod, mod_inv } from "./Math.js";
import { Point, CURVE } from "./Ed25519.js";
import { Ed25519PublicComponent } from "./Components/Schemes/Ed25519/Ed25519Components.js";

/**
 * @param {bigint} xi
 * @param {bigint[]} xs 
 * @param {bigint} m 
 * @returns {bigint}
 */
export function GetLi(xi, xs, m = CURVE.n) {
    var li = xs.filter(xj => xj != xi)
        .map(xj => mod(mod_inv(xj-xi, m) * xj), m)
        .reduce((li, num) => mod(li * num, m));
    return li;
}

/**
 * @param {bigint[]} ids 
 */
export function GetLis(ids){
	return ids.map(id => GetLi(id, ids, CURVE.n));
}

/**
 * 
 * @param {Point[]} points 
 */
export function AggregatePoints(points){
    if(points.every(p => p == null)) return null;
    else return points.reduce((sum, next) => next == null ? sum : sum.add(next), Point.ZERO);
}
/**
 * 
 * @param {Ed25519PublicComponent[]} points 
 */
export function AggregatePublicComponents(points){
    if(points.every(p => p == null)) return null;
    else return points.reduce((sum, next) => next == null ? sum : sum.AddComponent(next), new Ed25519PublicComponent(Point.ZERO));
}

/**
 * 
 * @param {Ed25519PublicComponent[]} pointArrays 
 */
export function AggregatePublicComponentArrays(pointArrays){
    const arrayDepth = pointArrays[0].length;
    if(!pointArrays.every(array => array.length == arrayDepth)) throw Error("Inconsistent amount of array depths");
    return pointArrays[0].map((_, i) => AggregatePublicComponents(pointArrays.map(array => array[i])));
}

/**
 * Will aggregate all points at corresponding indexes. E.g. all points from each array at index 0 will be summed.
 * @param {Point[][]} pointArrays 
 */
export function AggregatePointArrays(pointArrays){
    const arrayDepth = pointArrays[0].length;
    if(!pointArrays.every(array => array.length == arrayDepth)) throw Error("Inconsistent amount of array depths");
    return pointArrays[0].map((_, i) => AggregatePoints(pointArrays.map(array => array[i])));
}
/**
 * Will aggregate all points and multiply by corresponding li of id.
 * @param {Point[]} points 
 * @param {bigint[]} ids 
 * @returns {Point}
 */
export function AggregatePointsWithIds(points, ids){
    const lis = GetLis(ids);
    return AggregatePoints(points.map((p, i) => p.mul(lis[i])));
}
/**
 * Will aggregate all points and multiply by corresponding li.
 * @param {Point[]} points 
 * @param {bigint[]} lis 
 * @returns {Point}
 */
export function AggregatePointsWithLis(points, lis){
    return AggregatePoints(points.map((p, i) => p.mul(lis[i])));
}
