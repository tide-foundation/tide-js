import { sign, signAsync, signNonDeterministicAsync, verifyAsync } from "../../../Ed25519.js";
import BaseScheme from "../BaseScheme.js";
import { SchemeType } from "../SchemeRegistry.js";
import { Ed25519PrivateComponent, Ed25519PublicComponent, Ed25519SeedComponent } from "./Ed25519Components.js";

export default class Ed25519Scheme extends BaseScheme{
    static get Name() { return "Ed25519Scheme"; }
    /**
     * WITHOUT DETERMINISM. Prefix is generated via randomisation.
     * @returns 
     */
    GetSigningFunction = () => {
        const signingFunc = (msg, component) => {
            if(msg instanceof Uint8Array && component instanceof Ed25519PrivateComponent){
                return signNonDeterministicAsync(msg, component.priv);
            }
            throw Error("Mismatch of expected types (Uint8Array, Ed25519PrivateComponent)");
        }
        return signingFunc;
    }
    GetVerifyingFunction = () => {
        const verifyingFunc = (msg, signature, component) => {
            if(msg instanceof Uint8Array && signature instanceof Uint8Array && component instanceof Ed25519PublicComponent){
                return verifyAsync(signature, msg, component.rawBytes);
            }
            throw Error("Mismatch of expected types (Uint8Array, Uint8Array, Ed25519PublicComponent)");
        }
        return verifyingFunc;
    }
}