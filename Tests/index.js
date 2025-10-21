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

// Forseti – prompt-free + headless + dev panel
import {
  mountForsetiTester as Forseti_DevPanel
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
  Mobile_CMKAuth_Pairing,
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

  // Forseti (no prompts)
  Forseti_DevPanel                 // explicitly open the tester panel
};

window.tests = tests;
