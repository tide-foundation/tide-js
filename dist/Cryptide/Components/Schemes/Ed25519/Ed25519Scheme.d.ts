import BaseScheme from "../BaseScheme";
export default class Ed25519Scheme extends BaseScheme {
    static get Name(): string;
    /**
     * WITHOUT DETERMINISM. Prefix is generated via randomisation.
     * @returns
     */
    static GetSigningFunction: () => (msg: any, component: any) => Promise<any>;
    static GetVerifyingFunction: () => (msg: any, signature: any, component: any) => Promise<void>;
    static GetEncryptingFunction: () => (msg: any, component: any) => Promise<Uint8Array<any>>;
    static GetDecryptingFunction: () => (cipher: any, component: any) => Promise<Uint8Array<ArrayBuffer>>;
}
