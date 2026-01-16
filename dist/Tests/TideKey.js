"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = Tide_Key;
const Ed25519Scheme_ts_1 = __importDefault(require("../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.ts"));
const TideKey_ts_1 = __importDefault(require("../Cryptide/TideKey.ts"));
async function Tide_Key() {
    const k = TideKey_ts_1.default.NewKey(Ed25519Scheme_ts_1.default);
    const msg = new TextEncoder().encode("hello");
    const sig = await k.sign(msg);
    const v = TideKey_ts_1.default.FromSerializedComponent(k.get_public_component().Serialize().ToBytes());
    await v.verify(msg, sig);
    console.log("all g");
}
