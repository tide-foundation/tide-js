"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.tests = void 0;
const StripeLicensing_ts_1 = require("./StripeLicensing.ts");
const Components_ts_1 = require("./Components.ts");
const TideKey_ts_1 = __importDefault(require("./TideKey.ts"));
const Verifier_ts_1 = require("./Verifier.ts");
exports.tests = {
    StripeLicensing: StripeLicensing_ts_1.StripeLicensing,
    CheckLicenseAddedToPayer: StripeLicensing_ts_1.CheckLicenseAddedToPayer,
    Ed25519PublicDeserialization: Components_ts_1.Ed25519PublicDeserialization,
    Tide_Key: TideKey_ts_1.default,
    Verifier: Verifier_ts_1.Verifier
};
/**
 {
    "vendorId": "54f2c12e7c0c713e6107a5f8b76cc0ead5be1309069e2bca0df033b20f0f2fc2",
    "gVRK": "17ffad8068dc0de9935d36636f3ad1b5de6de3413b12388e453b05f2a4c1d3db"
 }
 */
//console.log(Bytes2Hex(Point.BASE.mul(BigInt("123456789")).toRawBytes()));
//const obfg = Bytes2Hex((await HashToPoint(Point.BASE.toRawBytes())).mul(BigIntFromByteArray(await SHA256_Digest(BigIntToByteArray(BigInt("123456789"))))).toRawBytes())
//console.log(obfg);
//console.log(Bytes2Hex((await HashToPoint(Point.BASE.toRawBytes())).toRawBytes()));
window.tests = exports.tests;
