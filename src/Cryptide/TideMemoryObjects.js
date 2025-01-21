import { CreateTideMemory, writeInt64LittleEndian, WriteValue } from "./Serialization.js";
import { Utils } from "../TideJS/index.js";
import { Ed25519PublicComponent } from "./Components/Schemes/Ed25519/Ed25519Components.js";
import { AuthorizerSignatureFormat } from "./Signing/TideSignature.js";

/**
 * 
 * @param {Ed25519PublicComponent} gvrk 
 * @param {number | bigint} expiry 
 */
export function CreateVRKPackage(gvrk, expiry){
    const serializedgvrk = gvrk.Serialize().ToBytes();
    const ex = typeof expiry == "bigint" ? expiry : BigInt(expiry);
    if(ex < BigInt(Utils.CurrentTime() + 5)) throw Error("Expiry must be at least 5 seconds into future");
    const time_b = writeInt64LittleEndian(ex);
    const vrk_pack = CreateTideMemory(serializedgvrk,
        4 + 4 + serializedgvrk.length + time_b.length
    );
    WriteValue(vrk_pack, 1, time_b);
    return vrk_pack;
}
/**
 * 
 * @param {string} authFlow 
 * @param {string[]} signModels 
 * @param {Uint8Array} vrk_pack 
 * @returns 
 */
export function CreateAuthorizerPackage(authFlow, signModels, vrk_pack){
    return new AuthorizerSignatureFormat(authFlow, signModels, vrk_pack).format();
}