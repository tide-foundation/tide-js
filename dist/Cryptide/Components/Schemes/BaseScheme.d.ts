export default class BaseScheme {
    static get Name(): void;
    /**@returns {(msg: Uint8Array, signature: Uint8Array, pub: BasePublicComponent) => Promise<(boolean)>} */
    static GetVerifyingFunction: () => never;
    /**@returns {(msg: Uint8Array, priv: BasePrivateComponent) => Promise<(Uint8Array)>} */
    static GetSigningFunction: () => never;
    static GetEncryptingFunction: () => never;
}
