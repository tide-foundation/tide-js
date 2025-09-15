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

import { Point } from "../../../../Cryptide/Ed25519.js";
import TideKey from "../../../../Cryptide/TideKey.js";


export default class DecryptedDeviceConvertResponse{
    /** 
     * @param {string} PRKRequesti
     * @param {bigint} Timestampi 
     * @param {number} Exti
     * @param {Point} UserPRISMi
     */
    constructor(PRKRequesti, Timestampi, Exti, UserPRISMi){
        this.PRKRequesti = PRKRequesti
        this.Timestampi = Timestampi
        this.Exti = Exti
        this.UserPRISMi = UserPRISMi;
    }
    static from(data){
        const obj = JSON.parse(data);
        const timestamp = BigInt(obj.Timestampi);
        const userPRISMi = TideKey.FromSerializedComponent(obj.UserPRISMi).get_public_component().public;
        return new DecryptedDeviceConvertResponse(obj.PRKRequesti, timestamp, obj.Exti, userPRISMi);
    }
}