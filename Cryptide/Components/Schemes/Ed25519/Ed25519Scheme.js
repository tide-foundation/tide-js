import { sign, signAsync, signNonDeterministicAsync, verifyAsync } from "../../../Ed25519.js";
import ElGamal from "../../../Encryption/ElGamal.js";
import BaseScheme from "../BaseScheme.js";
import { SchemeType } from "../SchemeRegistry.js";
import { Ed25519PrivateComponent, Ed25519PublicComponent, Ed25519SeedComponent } from "./Ed25519Components.js";

export default class Ed25519Scheme extends BaseScheme{
    static get Name() { return "Ed25519Scheme"; }
    /**
     * WITHOUT DETERMINISM. Prefix is generated via randomisation.
     * @returns 
     */
    static GetSigningFunction = () => {
        const signingFunc = (msg, component) => {
            if(msg instanceof Uint8Array && component instanceof Ed25519PrivateComponent){
                return signNonDeterministicAsync(msg, component.priv);
            }
            throw Error("Mismatch of expected types (Uint8Array, Ed25519PrivateComponent)");
        }
        return signingFunc;
    }
    static GetVerifyingFunction = () => {
        const verifyingFunc = async (msg, signature, component) => {
            if(msg instanceof Uint8Array && signature instanceof Uint8Array && component instanceof Ed25519PublicComponent){
                const valid = await verifyAsync(signature, msg, component.rawBytes);
                if(!valid) throw Error("Signature validation failed");
            }
            else throw Error("Mismatch of expected types (Uint8Array, Uint8Array, Ed25519PublicComponent)");
        }
        return verifyingFunc;
    }
    static GetEncryptingFunction = () => {
        const encryptingFunc = async (msg, component) => {
            if(msg instanceof Uint8Array && component instanceof Ed25519PublicComponent){
                return await ElGamal.encryptDataRaw(msg, component.public);
            }
            else throw Error("Mismatch between expected types (Uint8Array, Ed25519PublicComponent)");
        }
        return encryptingFunc;
    }
    static GetDecryptingFunction = () => {
        const decryptingFunc = async (cipher, component) => {
            if(cipher instanceof Uint8Array && component instanceof Ed25519PrivateComponent){
                return await ElGamal.decryptDataRaw(cipher, component.priv);
            }
            else throw Error("Mismatch between expected types (Uint8Array, Ed25519PrivateComponent)");
        }
        return decryptingFunc;
    }
}