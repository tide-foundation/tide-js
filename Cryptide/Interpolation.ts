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

import { mod, mod_inv } from "./Math";
import { Point, CURVE } from "./Ed25519";
import { Ed25519PublicComponent } from "./Components/Schemes/Ed25519/Ed25519Components";

export function GetLi(xi: bigint, xs: bigint[], m: bigint = CURVE.n): bigint {
    var li = xs.filter(xj => xj != xi)
        .map(xj => mod(mod_inv(xj-xi, m) * xj), m)
        .reduce((li, num) => mod(li * num, m));
    return li;
}

export function GetLis(ids: bigint[]){
	return ids.map(id => GetLi(id, ids, CURVE.n));
}

export function AggregatePoints(points: Point[]){
    if(points.every(p => p == null)) return null;
    else return points.reduce((sum, next) => next == null ? sum : sum.add(next), Point.ZERO);
}
export function AggregatePublicComponents(points: Ed25519PublicComponent[]){
    if(points.every(p => p == null)) return null;
    else return points.reduce((sum, next) => next == null ? sum : sum.AddComponent(next), new Ed25519PublicComponent(Point.ZERO));
}

export function AggregatePublicComponentArrays(pointArrays: Ed25519PublicComponent[][]){
    const arrayDepth = pointArrays[0].length;
    if(!pointArrays.every(array => array.length == arrayDepth)) throw Error("Inconsistent amount of array depths");
    return pointArrays[0].map((_, i) => AggregatePublicComponents(pointArrays.map(array => array[i])));
}

/**
 * Will aggregate all points at corresponding indexes. E.g. all points from each array at index 0 will be summed.
 */
export function AggregatePointArrays(pointArrays: Point[][]){
    const arrayDepth = pointArrays[0].length;
    if(!pointArrays.every(array => array.length == arrayDepth)) throw Error("Inconsistent amount of array depths");
    return pointArrays[0].map((_, i) => AggregatePoints(pointArrays.map(array => array[i])));
}
/**
 * Will aggregate all points and multiply by corresponding li of id.
 */
export function AggregatePointsWithIds(points: Point[], ids: bigint[]): Point {
    const lis = GetLis(ids);
    return AggregatePoints(points.map((p, i) => p.mul(lis[i])));
}
/**
 * Will aggregate all points and multiply by corresponding li.
 */
export function AggregatePointsWithLis(points: Point[], lis: bigint[]): Point {
    return AggregatePoints(points.map((p, i) => p.mul(lis[i])));
}
