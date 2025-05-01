import { BasePrivateComponent, BasePublicComponent } from "../BaseComponent";

export default class BaseScheme{
    static get Name() { throw Error("Name not implemented"); }
    /**@returns {(msg: Uint8Array, signature: Uint8Array, pub: BasePublicComponent) => Promise<(boolean)>} */
    GetVerifyingFunction = () => { throw Error("Verifying function not implemented"); }
    /**@returns {(msg: Uint8Array, priv: BasePrivateComponent) => Promise<(Uint8Array)>} */
    GetSigningFunction = () => { throw Error("Signing function not implemented"); }
    GetEncryptingFunction = () => { throw Error("Encrypting function not implemented"); }
}