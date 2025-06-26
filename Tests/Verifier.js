import { EdDSA } from "../Cryptide/index.js";

export async function Verifier() {
    const key = window.prompt("Base64 public key");
    const message = window.prompt("Message to verify");
    const sig = window.prompt("Base64 signature");

    const valid = await EdDSA.verify(sig, key, message);
    console.log("The signature is " + valid);
}