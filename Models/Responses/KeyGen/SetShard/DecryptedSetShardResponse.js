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

import { BigIntFromByteArray, base64ToBytes } from "../../../../Cryptide/Serialization.js";

export default class DecryptedSetShardResponse{
    /**
     * @param {bigint} Si 
     * @param {bigint[] | null} VRK_Si
     */
    constructor(Si, VRK_Si=null){
        this.Si = Si
        this.VRK_Si = VRK_Si;
    }

    static from(data){
        const obj = JSON.parse(data);
        const si = BigIntFromByteArray(base64ToBytes(obj.Si));
        let vrk_si = null;
        if(obj.VRK_Si != undefined) vrk_si = obj.VRK_Si.map(si => BigIntFromByteArray(base64ToBytes(si))); 
        return new DecryptedSetShardResponse(si, vrk_si);
    }
}