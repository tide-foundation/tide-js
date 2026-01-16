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
exports.GetKeys = GetKeys;
const Hash_1 = require("../Cryptide/Hashing/Hash");
const Interpolation_1 = require("../Cryptide/Interpolation");
/**
 *
 * @param {Point[][]} appliedC1s
 * @param {bigint[]} ids
 */
async function GetKeys(appliedC1s, ids) {
    // Apply Lis to points, sum result
    const lis = (0, Interpolation_1.GetLis)(ids);
    const appliedC1sWithLi = appliedC1s.map((c1, i) => c1.map(c => c.mul(lis[i])));
    return Promise.all((0, Interpolation_1.AggregatePointArrays)(appliedC1sWithLi).map(async (p) => (0, Hash_1.SHA256_Digest)(p.toRawBytes())));
}
