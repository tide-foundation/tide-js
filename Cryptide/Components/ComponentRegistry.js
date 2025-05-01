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