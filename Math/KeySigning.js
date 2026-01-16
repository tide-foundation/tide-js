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

import { Point } from "../Cryptide/Ed25519.js";
import { mod } from "../Cryptide/Math.js";

/**
 * @param {Point[][]} GRij 
 */
export function PreSign(GRij){
    if(!GRij.every(Gri => Gri.length == GRij[0].length)) throw new Error("Orks returned different amount of Grs");
    return GRij[0].map((_, i) => GRij.reduce((sum, next) => sum.add(next[i]), Point.ZERO));
}

/**
 * 
 * @param {BigInt[][]} Sis 
 */
export function Sign(Sis){
    if(!Sis.every(Si => Si.length == Sis[0].length)) throw new Error("Orks returned different amount of Si");
    return Sis[0].map((_, i) => mod(Sis.reduce((sum, next) => sum + next[i], BigInt(0))));
}