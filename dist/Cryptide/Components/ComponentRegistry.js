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
exports.Registery = exports.Ed25519SeedComponentFactory = exports.Ed25519PrivateComponentFactory = exports.Ed25519PublicComponentFactory = void 0;
const Ed25519Components_1 = require("./Schemes/Ed25519/Ed25519Components");
class Ed25519PublicComponentFactory {
    static Create(b) {
        return new Ed25519Components_1.Ed25519PublicComponent(b);
    }
}
exports.Ed25519PublicComponentFactory = Ed25519PublicComponentFactory;
class Ed25519PrivateComponentFactory {
    static Create(b) {
        return new Ed25519Components_1.Ed25519PrivateComponent(b);
    }
}
exports.Ed25519PrivateComponentFactory = Ed25519PrivateComponentFactory;
class Ed25519SeedComponentFactory {
    static Create(b) {
        return new Ed25519Components_1.Ed25519SeedComponent(b);
    }
}
exports.Ed25519SeedComponentFactory = Ed25519SeedComponentFactory;
exports.Registery = {
    Ed25519Scheme: {
        Public: Ed25519PublicComponentFactory,
        Private: Ed25519PrivateComponentFactory,
        Seed: Ed25519SeedComponentFactory
    }
};
