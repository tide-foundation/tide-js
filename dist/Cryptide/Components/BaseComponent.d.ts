export declare class BaseComponent {
    constructor();
    static Name: () => never;
    static Version: () => never;
    Add(component: any): void & BaseComponent;
    Multiply(component: any): void & BaseComponent;
    Minus(component: any): void & BaseComponent;
    Equals(component: any): never;
    Mod(): void & BaseComponent;
    ModInv(): void & BaseComponent;
    AddComponent(component: any): void;
    MultiplyComponent(component: any): void;
    MinusComponent(component: any): void;
    EqualsComponent(component: any): void;
    ModComponent(): void;
    ModInvComponent(): void;
    SerializeComponent(): void;
    /**@returns {BaseScheme} */
    get Scheme(): void;
    /**@returns {string} */
    get ComponentType(): void;
    /**
     *
     * @returns {SerializedComponent}
     */
    Serialize(): SerializedComponent;
    /**
    * @param {Uint8Array|string} serialized
    * @returns {BaseComponent}
    */
    static DeserializeComponent(serialized: any): any;
}
export declare class BaseSeedComponent extends BaseComponent {
    get ComponentType(): string;
    static New(): void;
    GetPublic(): void;
    GetPrivate(): void;
    get rawBytes(): void;
}
export declare class BasePrivateComponent extends BaseComponent {
    get ComponentType(): string;
    static New(): void;
    GetPublic(): void;
    get priv(): void;
}
export declare class BasePublicComponent extends BaseComponent {
    get ComponentType(): string;
    get public(): void;
}
export declare class SerializedComponent {
    Bytes: any;
    ComponentType: any;
    constructor(bytes: any, compentType: any);
    ToBytes(): any;
    ToString(): any;
}
export declare const Seed = "Seed";
export declare const Private = "Private";
export declare const Public = "Public";
export declare const Symmetric = "Symmetric";
export declare const QuantumPrivate = "QuantumPrivate";
export declare const QuantumPublic = "QuantumPublic";
