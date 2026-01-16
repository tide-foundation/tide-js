import { BaseSeedComponent, BasePrivateComponent, BasePublicComponent } from "../../BaseComponent";
import Ed25519Scheme from "./Ed25519Scheme";
export declare class Ed25519PublicComponent extends BasePublicComponent {
    static Name: string;
    static Version: string;
    get Scheme(): typeof Ed25519Scheme;
    get ComponentType(): string;
    /**@type {Uint8Array} */
    pb: any;
    /**@type {Point} */
    p: any;
    constructor(rawData: any);
    get public(): any;
    get rawBytes(): any;
    AddComponent(component: any): Ed25519PublicComponent;
    MultiplyComponent(component: any): Ed25519PublicComponent;
    MinusComponent(component: any): Ed25519PublicComponent;
    EqualsComponent(component: any): any;
    SerializeComponent(): any;
}
export declare class Ed25519PrivateComponent extends BasePrivateComponent {
    static Name: string;
    static Version: string;
    get Scheme(): typeof Ed25519Scheme;
    get ComponentType(): string;
    /**@type {bigint} */
    p: any;
    /**@type {Uint8Array} */
    rB: any;
    get priv(): any;
    get rawBytes(): any;
    constructor(rawData: any);
    SerializeComponent(): any;
    GetPublic(): Ed25519PublicComponent;
    static New(): Ed25519PrivateComponent;
}
export declare class Ed25519SeedComponent extends BaseSeedComponent {
    static Name: string;
    static Version: string;
    get Scheme(): typeof Ed25519Scheme;
    get ComponentType(): string;
    /**@type {Uint8Array} */
    rB: any;
    get rawBytes(): any;
    constructor(rawData: any);
    SerializeComponent(): any;
    static GenerateSeed(): Uint8Array<any>;
    GetPrivate(): Ed25519PrivateComponent;
    GetPublic(): Ed25519PublicComponent;
    static New(): Ed25519SeedComponent;
}
