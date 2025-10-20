import { NewCMK_NewPRISM, ExistingCMK_NewPRISM, NewVVK, HealPrism } from "./KeyGeneration.js";
import {
    CMKAuth_Basic,
    CMKAuth_Remembered,
    Mobile_Authentication_Real_Login,
    Mobile_Authentication_Real_Pairing,
    Mobile_Authentication_Real_SignUp,
    Mobile_CMKAuth_Pairing
} from "./KeyAuthentication.js";
import { EmailRecovery } from "./AccountRecovery.js";
import { StripeLicensing, CheckLicenseAddedToPayer } from "./StripeLicensing.js";
import { Ed25519PublicDeserialization } from "./Components.js";
import { Decrypt, Encrypt, Get_Auth_By_JWT } from "./Encryption.js";
import Tide_Key from "./TideKey.js";
import { Verifier } from "./Verifier.js";
import { EnclaveToMobileTunnelling_Enclave, EnclaveToMobileTunnelling_Mobile } from "./Tunelling.js";

// New Forseti policy E2E tests (upload/bind/validate, deny case, revoke)
import {
    Forseti_UploadBindValidate,
    Forseti_UploadBindExpectDeny,
    Forseti_RevokeBh
} from "./ForsetiPolicyTests.js";

export const tests = {
    // Payments/Licensing
    StripeLicensing,
    CheckLicenseAddedToPayer,

    // Key Gen / Auth
    NewCMK_NewPRISM,
    ExistingCMK_NewPRISM,
    CMKAuth_Basic,
    CMKAuth_Remembered,
    NewVVK,
    HealPrism,

    // Auth flows (web/mobile)
    Mobile_CMKAuth_Pairing: Mobile_CMKAuth_Pairing,
    Mobile_Authentication_Real_Pairing,
    Mobile_Authentication_Real_Login,
    Mobile_Authentication_Real_SignUp,

    // Crypto / Components
    Ed25519PublicDeserialization,
    Get_Auth_By_JWT,
    Encrypt,
    Decrypt,
    Tide_Key,
    Verifier,

    // Tunneling
    EnclaveToMobileTunnelling_Enclave,
    EnclaveToMobileTunnelling_Mobile,

    // New Forseti policy tests (prod endpoints, runtime-provided data)
    Forseti_UploadBindValidate,
    Forseti_UploadBindExpectDeny,
    Forseti_RevokeBh
};

/**
 {
    "vendorId": "54f2c12e7c0c713e6107a5f8b76cc0ead5be1309069e2bca0df033b20f0f2fc2",
    "gVRK": "17ffad8068dc0de9935d36636f3ad1b5de6de3413b12388e453b05f2a4c1d3db"
 }
 */

window.tests = tests;
