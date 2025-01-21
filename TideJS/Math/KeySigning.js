import { mod } from "../../Cryptide/Math.js";
import { Point } from "../../Cryptide/index.js";

/**
 * @param {Point[][]} GRij 
 */
export function PreSign(GRij){
    if(!GRij.every(Gri => Gri.length == GRij[0].length)) throw new Error("Orks returned different amount of Grs");
    return GRij[0].map((_, i) => GRij.reduce((sum, next) => sum.add(next[i]), Point.infinity));
}

/**
 * 
 * @param {BigInt[][]} Sis 
 */
export function Sign(Sis){
    if(!Sis.every(Si => Si.length == Sis[0].length)) throw new Error("Orks returned different amount of Si");
    return Sis[0].map((_, i) => mod(Sis.reduce((sum, next) => sum + next[i], BigInt(0))));
}