import { Signing } from "../Cryptide/index";

export async function Verifier() {
    const key = window.prompt("Base64 public key");
    const message = window.prompt("Message to verify");
    const sig = window.prompt("Base64 signature");

    const valid = await Signing.EdDSA.verify(sig, key, message);
    console.log("The signature is " + valid);
}