"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Ed25519PublicDeserialization = Ed25519PublicDeserialization;
const Ed25519Components_ts_1 = require("../Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts");
const Ed25519_ts_1 = require("../Cryptide/Ed25519.ts");
async function Ed25519PublicDeserialization() {
    const gComp = new Ed25519Components_ts_1.Ed25519PublicComponent(Ed25519_ts_1.Point.BASE);
    const serial = gComp.Serialize().ToString();
    console.log(serial);
    const newG = Ed25519Components_ts_1.Ed25519PublicComponent.DeserializeComponent(serial);
    console.log(newG);
    const one = new Ed25519Components_ts_1.Ed25519PrivateComponent(BigInt(1));
    const oserial = one.Serialize().ToString();
    console.log(oserial);
    const none = Ed25519Components_ts_1.Ed25519PrivateComponent.DeserializeComponent(oserial);
    console.log(none);
}
