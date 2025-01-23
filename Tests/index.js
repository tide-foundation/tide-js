import { NewCMK_NewPRISM, ExistingCMK_NewPRISM, NewVVK, HealPrism } from "./KeyGeneration.js";
import { CMKAuth_Basic, CMKAuth_Remembered } from "./KeyAuthentication.js";
import { EmailRecovery } from "./AccountRecovery.js";
import { StripeLicensing, CheckLicenseAddedToPayer } from "./StripeLicensing.js"
import { Ed25519PublicDeserialization } from "./Components.js";
import { Encrypt_auth_by_jwt } from "./Encryption.js";

export const tests = {
    StripeLicensing,
    CheckLicenseAddedToPayer,
    NewCMK_NewPRISM, 
    ExistingCMK_NewPRISM,
    CMKAuth_Basic,
    CMKAuth_Remembered,
    EmailRecovery,
    NewVVK,
    HealPrism,
    Ed25519PublicDeserialization,
    Encrypt_auth_by_jwt
};

/**
 {
    "vendorId": "54f2c12e7c0c713e6107a5f8b76cc0ead5be1309069e2bca0df033b20f0f2fc2",
    "gVRK": "17ffad8068dc0de9935d36636f3ad1b5de6de3413b12388e453b05f2a4c1d3db"
 }
 */
//console.log(Bytes2Hex(Point.g.times(BigInt("123456789")).toArray()));
//const obfg = Bytes2Hex((await HashToPoint(Point.g.toArray())).times(BigIntFromByteArray(await SHA256_Digest(BigIntToByteArray(BigInt("123456789"))))).toArray())
//console.log(obfg);
//console.log(Bytes2Hex((await HashToPoint(Point.g.toArray())).toArray()));
window.tests = tests;