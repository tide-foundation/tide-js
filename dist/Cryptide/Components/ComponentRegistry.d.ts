import { Ed25519PrivateComponent, Ed25519PublicComponent, Ed25519SeedComponent } from "./Schemes/Ed25519/Ed25519Components";
export declare class Ed25519PublicComponentFactory {
    static Create(b: any): Ed25519PublicComponent;
}
export declare class Ed25519PrivateComponentFactory {
    static Create(b: any): Ed25519PrivateComponent;
}
export declare class Ed25519SeedComponentFactory {
    static Create(b: any): Ed25519SeedComponent;
}
export declare const Registery: {
    Ed25519Scheme: {
        Public: typeof Ed25519PublicComponentFactory;
        Private: typeof Ed25519PrivateComponentFactory;
        Seed: typeof Ed25519SeedComponentFactory;
    };
};
