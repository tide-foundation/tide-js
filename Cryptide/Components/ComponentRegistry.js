import {  Ed25519PrivateComponent, Ed25519PublicComponent } from "./Schemes/Ed25519/Ed25519Components.js";

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

export const Registery = {
    Ed25519Scheme : {
        Public : Ed25519PublicComponentFactory,
        Private : Ed25519PrivateComponentFactory
    }
};