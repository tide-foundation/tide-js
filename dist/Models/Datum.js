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
const Serialization_1 = require("../Cryptide/Serialization");
// FieldData on Heimdall turns into Datum on enclave
class Datum {
    /**
     * @param {string|Uint8Array} Data
     * @param {number} Tag
     */
    constructor(Data, Tag) {
        this.data = typeof (Data) == "string" ? (0, Serialization_1.base64ToBytes)(Data) : Data;
        this.tag = Tag;
    }
    static fromJSON(json) {
        return new Datum(json.Data, json.Tag);
    }
    toObject() {
        return {
            Data: (0, Serialization_1.bytesToBase64)(this.data),
            Tag: this.tag
        };
    }
}
exports.default = Datum;
