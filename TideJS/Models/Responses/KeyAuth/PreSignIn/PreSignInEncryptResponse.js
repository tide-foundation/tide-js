import { Point } from "../../../../../Cryptide/index.js";

export default class PreSignInEncryptResponse{
    /**
     * @param {Point[]} gCVKRin 
     */
    constructor(gCVKRin){
        this.gCVKRin = gCVKRin
    }

    static from(data){
        const obj = JSON.parse(data);
        const gCVKRin = obj.gCVKRin.map(p => Point.fromB64(p));
        return new PreSignInEncryptResponse(gCVKRin);
    }
}