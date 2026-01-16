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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ClientBase_1 = __importDefault(require("./ClientBase"));
const VoucherResponse_1 = __importDefault(require("../Models/Responses/Vendor/VoucherResponse"));
class VoucherClient extends ClientBase_1.default {
    /**
     * @param {string} url
     */
    constructor(url) {
        super(url);
    }
    /**
     *
     * @param {Point[]} blurPORKi
     * @param {string} actionRequest
     * @param {Point} blurerK
     */
    async GetVouchers(blurPORKi, actionRequest, blurerK) {
        const request = JSON.stringify({
            BlurPORKi: blurPORKi.map(blur => blur.toBase64()),
            ActionRequest: actionRequest,
            BlurerK: blurerK.toBase64()
        });
        const data = this._createFormData({
            'voucherRequest': request
        });
        const response = await this._post(``, data);
        const respondeData = await this._handleError(response, "Get Vouchers", true);
        return VoucherResponse_1.default.from(respondeData, blurerK.toBase64());
    }
}
exports.default = VoucherClient;
