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

import { Point } from "../../../Cryptide/index.js";
export default class CMKConvertResponse{
    /** 
     * @param {string} EncRequesti
     * @param {Point} GCMKRi
     */
    constructor(EncRequesti, GCMKRi){
        this.EncChallengei = EncRequesti
        this.GCMKRi = GCMKRi
    }
    static from(data){
        const obj = JSON.parse(data);
        const gCMKRi = Point.fromB64(obj.GCMKRi)
        return new CMKConvertResponse(obj.EncRequesti, gCMKRi);
    }
}