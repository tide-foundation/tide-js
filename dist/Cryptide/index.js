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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Serialization = exports.Math = exports.Interpolation = exports.HashToPoint = exports.Hash = exports.EdDSA = exports.DH = exports.AES = exports.ElGamal = void 0;
var ElGamal_1 = require("./Encryption/ElGamal");
Object.defineProperty(exports, "ElGamal", { enumerable: true, get: function () { return __importDefault(ElGamal_1).default; } });
const AES = __importStar(require("./Encryption/AES"));
exports.AES = AES;
const DH = __importStar(require("./Encryption/DH"));
exports.DH = DH;
const EdDSA = __importStar(require("./Signing/EdDSA"));
exports.EdDSA = EdDSA;
const Hash = __importStar(require("./Hashing/Hash"));
exports.Hash = Hash;
const HashToPoint = __importStar(require("./Hashing/H2P"));
exports.HashToPoint = HashToPoint;
const Interpolation = __importStar(require("./Interpolation"));
exports.Interpolation = Interpolation;
const Math = __importStar(require("./Math"));
exports.Math = Math;
const Serialization = __importStar(require("./Serialization"));
exports.Serialization = Serialization;
