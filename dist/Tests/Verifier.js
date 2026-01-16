"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Verifier = Verifier;
const index_ts_1 = require("../Cryptide/index.ts");
async function Verifier() {
    const key = window.prompt("Base64 public key");
    const message = window.prompt("Message to verify");
    const sig = window.prompt("Base64 signature");
    const valid = await index_ts_1.EdDSA.verify(sig, key, message);
    console.log("The signature is " + valid);
}
