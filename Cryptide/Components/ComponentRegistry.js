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

import {  Ed25519PrivateComponent, Ed25519PublicComponent, Ed25519SeedComponent } from "./Schemes/Ed25519/Ed25519Components.js";

export class Ed25519PublicComponentFactory{
    static Create(b){
        return new Ed25519PublicComponent(b);
    }
}

export class Ed25519PrivateComponentFactory{
    static Create(b){
        return new Ed25519PrivateComponent(b);
    }
}

export class Ed25519SeedComponentFactory{
    static Create(b){
        return new Ed25519SeedComponent(b);
    }
}

export const Registery = {
    Ed25519Scheme : {
        Public : Ed25519PublicComponentFactory,
        Private : Ed25519PrivateComponentFactory,
        Seed : Ed25519SeedComponentFactory
    }
};