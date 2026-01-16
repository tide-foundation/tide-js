"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
class VoucherResponse {
    /**
     *
     * @param {string[]} voucherPacks
     * @param {string} qPub
     * @param {string} payerPub
     * @param {string} YHat
     * @param {string} blurerK
     * @param {string} UDeObf
     */
    constructor(voucherPacks, qPub, payerPub, Yhat, blurerK, UDeObf) {
        this.voucherPacks = voucherPacks;
        this.qPub = qPub;
        this.payerPub = payerPub;
        this.Yhat = Yhat;
        this.blurerK = blurerK;
        this.UDeObf = UDeObf;
    }
    static from(data, blurerK) {
        const json = JSON.parse(data);
        return new VoucherResponse(json.voucherPacks, json.QPub, json.PayerPub, json.YHat, blurerK, json.UDeObf);
    }
    /**
     *
     * @param {number} index
     * @returns
     */
    toORK(index) {
        return JSON.stringify({
            VoucherPack: this.voucherPacks[index],
            YHat: this.Yhat,
            QPub: this.qPub,
            BlurerK: this.blurerK,
            PayerPublic: this.payerPub
        });
    }
}
exports.default = VoucherResponse;
