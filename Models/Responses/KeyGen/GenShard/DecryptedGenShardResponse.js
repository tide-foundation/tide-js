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

import { Ed25519PublicComponent } from "../../../../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import { Point } from "../../../../Cryptide/index.js";
export default class DecryptedGenShardResponse{
    /** 
     * @param {Point} GRi
     * @param {bigint} Timestampi 
     * @param {Ed25519PublicComponent[]} GMultiplied
     * @param {Ed25519PublicComponent} GK1i
     * @param {Point[] | null} VRK_GR
     */
    constructor(GRi, Timestampi, GMultiplied, GK1i, VRK_GR=null){
        this.GRi = GRi
        this.Timestampi = Timestampi
        this.GMultiplied = GMultiplied
        this.GK1i = GK1i
        this.VRK_GR = VRK_GR;
    }
    static from(data){
        const obj = JSON.parse(data);
        const timestampi = BigInt(obj.Timestampi);
        const gRi = obj.GRi != null ? Point.fromB64(obj.GRi) : null;
        const gMultiplied = obj.GMultiplied.map(p => p == null ? null : Ed25519PublicComponent.DeserializeComponent(p));
        const gK1i = Ed25519PublicComponent.DeserializeComponent(obj.GK1i);
        let VRK_GR = null;
        if(obj.VRK_GRi != undefined) VRK_GR = obj.VRK_GRi.map(gr => Point.fromB64(gr));
        return new DecryptedGenShardResponse(gRi, timestampi, gMultiplied, gK1i, VRK_GR);
    }
}