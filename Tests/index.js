import { StripeLicensing, CheckLicenseAddedToPayer } from "./StripeLicensing.js"
import { Ed25519PublicDeserialization } from "./Components.js";
import { Decrypt, Encrypt, Get_Auth_By_JWT } from "./Encryption.js";
import Tide_Key from "./TideKey.js";
import { Verifier } from "./Verifier.js";
import {EnclaveToMobileTunnelling_Enclave, EnclaveToMobileTunnelling_Mobile } from "./Tunelling.js";

export const tests = {
    StripeLicensing,
    CheckLicenseAddedToPayer,
    Ed25519PublicDeserialization,
    Get_Auth_By_JWT,
    Encrypt,
    Decrypt,
    Tide_Key,
    Verifier
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
window.tests = tests;