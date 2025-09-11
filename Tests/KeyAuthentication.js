import OrkInfo from "../Models/Infos/OrkInfo.js";
import HashToPoint from "../Cryptide/Hashing/H2P.js";
import { AES, DH, Serialization } from "../Cryptide/index.js";
import { HMAC_forHashing } from "../Cryptide/Hashing/Hash.js";
import dCMKPasswordFlow from "../Flow/AuthenticationFlows/dCMKPasswordFlow.js";
import dCMKPasswordlessFlow from "../Flow/AuthenticationFlows/dCMKPasswordlessFlow.js";
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js";
import { Math } from "../Cryptide/index.js";
import { CreateGPrismAuth, GetPublic } from "../Cryptide/Math.js";
import EnclaveEntry from "../Models/EnclaveEntry.js";
import KeyInfo from "../Models/Infos/KeyInfo.js";
import NetworkClient from "../Clients/NetworkClient.js";
import { Max, sortORKs } from "../Tools/Utils.js";
import TideKey from "../Cryptide/TideKey.js";
import { base64ToBytes, BigIntFromByteArray, bytesToBase64, CreateTideMemoryFromArray, StringFromUint8Array, StringToUint8Array } from "../Cryptide/Serialization.js";
import EnclaveToMobileTunnelClient from "../Clients/EnclaveToMobileTunnelClient.js";
import dMobileAuthenticationFlow from "../Flow/AuthenticationFlows/dMobileAuthenticationFlow.js";
import Ed25519Scheme from "../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js";
import { Ed25519PrivateComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";

export async function CMKAuth_Basic(){
    // basic username, password test flow
    var orks;
    let i = 0;
    while(i < 1){
        const user = Date.now().toString();
        const persona = "1";
        const emails = ["testEmail1@doge.com"]

        const password = "pass";

        const gPass =  await HashToPoint(password);
        const uid = await Serialization.GetUID(user);
        const sessKey = Math.GenSessKey();
        const gSessKey = Math.GetPublic(sessKey);
        const sessID = "123ID";
        const VRK = BigInt(123456789);
        const gVRK = GetPublic(VRK);
        let GK;

        const create = async() => {
            // create account first
            const purpose = "NEW";
            const {reservationConfirmation, activeOrks} = (await dKeyGenerationFlow.ReserveUID(uid, "http://localhost:3000/voucher/new", gSessKey));
            orks = activeOrks.slice(0, Max);
            const genFlow = new dKeyGenerationFlow(uid, gVRK.toBase64(), orks, sessKey, gSessKey, purpose, "http://host.docker.internal:3000/voucher/new", emails);
            const {gMultiplied, gK} = await genFlow.GenShard(2, [null, gPass], reservationConfirmation); // auths can be null if purpose is "new", for now...
            GK = gK;
            const gPrismAuth = await CreateGPrismAuth(gMultiplied[1]);
            await genFlow.SetShard(gPrismAuth.toBase64(), "CMK");
            await genFlow.Commit();
        }

        const authenticate = async () => {
            const skey = TideKey.NewKey(Ed25519Scheme);
            const keyInfo = await new NetworkClient("http://host.docker.internal:1001").GetKeyInfo(uid);
            const dAuthFlow = new dCMKPasswordFlow(keyInfo, sessID, true, true, "http://host.docker.internal:3000/voucher/new");
            await dAuthFlow.Convert(skey, gPass, GK, true);
            await dAuthFlow.Authenticate(gSessKey); // gVRK can be anything for testing
        }

        await create();

        await authenticate();

        console.log("CMKAuth_Basic TEST SUCCESSFUL: " + i);
        i++;
    }
}

export async function CMKAuth_Remembered(){
    // authentication flow, provided valid EnclaveEntry (no password required)
    var orks;
    let i = 0;
    while(i < 1){
        const user = Date.now().toString();
        const persona = "1";
        const emails = ["testEmail1@doge.com"]
        const password = "pass";

        const gPass =  await HashToPoint(password);
        const uid = await Serialization.GetUID(user);
        const sessKey = Math.GenSessKey();
        const gSessKey = Math.GetPublic(sessKey);
        const sessID = "123ID";
        const VRK = BigInt(123456789);
        const gVRK = GetPublic(VRK);
        let GK;
        let keyM; 

        const create = async() => {
            // create account first
            const purpose = "NEW";
            const {reservationConfirmation, activeOrks} = (await dKeyGenerationFlow.ReserveUID(uid, "http://localhost:3000/voucher/new", gSessKey));
            orks = activeOrks.slice(0, Max);
            const genFlow = new dKeyGenerationFlow(uid, gVRK.toBase64(), orks, sessKey, gSessKey, purpose, "http://localhost:3000/voucher/new", emails);
            const {gMultiplied, gK} = await genFlow.GenShard(2, [null, gPass], reservationConfirmation); // auths can be null if purpose is "new", for now...
            GK = gK;
            const gPrismAuth = await CreateGPrismAuth(gMultiplied[1]);
            await genFlow.SetShard(gPrismAuth.toBase64(), "CMK");
            await genFlow.Commit();
        }

        const authenticate = async () => {
            const skey = new TideKey(new Ed25519PrivateComponent(BigIntFromByteArray(sessKey)));
            
            const keyInfo = await new NetworkClient("http://localhost:1001").GetKeyInfo(uid);
            const dAuthFlow = new dCMKPasswordFlow(keyInfo, sessID, true, true, "http://localhost:3000/voucher/new");
            await dAuthFlow.Convert(skey, gPass, GK, true);
            const {bitwise, expired, selfRequesti} = await dAuthFlow.Authenticate(gSessKey); // gVRK can be anything for testing
            const userInfo = new KeyInfo(uid, GK, keyInfo.UserM, orks);
            const auth = new EnclaveEntry(user, "1", BigInt(expired), userInfo, bitwise, selfRequesti, skey.get_private_component().Serialize().ToBytes());
            return auth;
        }

        const authenticateNoPassword = async(auth) => {
            const noPassFlow = new dCMKPasswordlessFlow(sessID, auth, "http://localhost:3000/voucher/new");
            await noPassFlow.ConvertRemembered();
            await noPassFlow.AuthenticateRemembered(gSessKey);
        }

        await create();
        const auth = await authenticate();
        await authenticateNoPassword(auth);

        console.log("CMKAuth_Remembered TEST SUCCESSFUL: " + i);
        i++;
    }
    
}

export async function Mobile_CMKAuth_Pairing(){
    // Enclave variables
    const voucherURL = "http://localhost:3000/voucher/new";
    const browserKey = TideKey.NewKey(Ed25519Scheme);
    const vendorPublicKey = browserKey;

    const returnURL = "http://returnURL";
    const returnURLSig = await vendorPublicKey.sign(StringToUint8Array(returnURL));
    const signedReturnURL = CreateTideMemoryFromArray([StringToUint8Array(returnURL), returnURLSig]);
    
    const sessionKey = browserKey;
    const sessionKeySig = bytesToBase64(await sessionKey.sign(browserKey.get_public_component().Serialize().ToBytes()));;

    const appReq = JSON.stringify({
      gSessKeyPub: sessionKey.get_public_component().Serialize().ToString(),
      sessionId: "sessionID",
      returnURL: returnURL
    });
    const appReqSig = bytesToBase64(await browserKey.sign(StringToUint8Array(appReq)));


    // Enclave initiates a tunnel with orks - provided an invite link
    const homeOrkUrl = "http://localhost:1001";
    const enclaveClient = new EnclaveToMobileTunnelClient(homeOrkUrl);
    const inviteLink = await enclaveClient.initializeConnection();
    const pre_mobileDone = enclaveClient.passEnclaveInfo(voucherURL, browserKey, appReq, appReqSig, sessionKey, sessionKeySig, vendorPublicKey);




    // Create user we can pair phone to
    const user = Date.now().toString();
    const persona = "1";
    const emails = ["testEmail1@doge.com"]
    const password = "pass";

    const gPass =  await HashToPoint(password);
    const uid = await Serialization.GetUID(user);
    const sessKey = Math.GenSessKey();
    const gSessKey = Math.GetPublic(sessKey);
    const sessID = "123ID";
    const VRK = BigInt(123456789);
    const gVRK = GetPublic(VRK);
    let GK;
    let keyM; 
    let orks;

    const create = async() => {
        // create account first
        const purpose = "NEW";
        const {reservationConfirmation, activeOrks} = (await dKeyGenerationFlow.ReserveUID(uid, "http://localhost:3000/voucher/new", gSessKey));
        orks = activeOrks.slice(0, Max);
        const genFlow = new dKeyGenerationFlow(uid, gVRK.toBase64(), orks, sessKey, gSessKey, purpose, "http://localhost:3000/voucher/new", emails);
        const {gMultiplied, gK} = await genFlow.GenShard(2, [null, gPass], reservationConfirmation); // auths can be null if purpose is "new", for now...
        GK = gK;
        const gPrismAuth = await CreateGPrismAuth(gMultiplied[1]);
        await genFlow.SetShard(gPrismAuth.toBase64(), "CMK");
        await genFlow.Commit();
    }

    await create();

    console.log("Now it begins");

    // Mobile authentication flow begins
    const mobileAuthFlow = new dMobileAuthenticationFlow(inviteLink);
    const deviceKey = TideKey.NewKey(Ed25519Scheme);
    const data = await mobileAuthFlow.ensureReady(user);
    const pre_pairDone = mobileAuthFlow.pairNewDevice(deviceKey.get_private_component().Serialize().ToString(), password, false, sessionKey); // <- remember me set here

    // Enclave client recieves mobile authentication data
    const mobileDone = await pre_mobileDone;

    // Enclave checks it can decrypt the encrypted data
    const decrpytedMobileData = JSON.parse(StringFromUint8Array(await sessionKey.asymmetricDecrypt(base64ToBytes(mobileDone))));

    // Check values inside decryptedMobileData are as expected
    const requiredProperties = ['prkRequesti', 'vendorData', 'rememberMe', 'enclaveEntry',];

    for (const property of requiredProperties) {
        if (Object.keys(decrpytedMobileData).indexOf(property) == -1) {
            throw new Error(`The decrpytedMobileData object is missing the required '${property}' property.`);
        }
    }

    // Now let's use these values to log in for real 
    // verify blind sig
    await enclaveClient.indicateSuccess();
    await pre_pairDone; // await the finalization of the commit

    // PAIRING DONE -------------
    // Now let's try a log in with the self requestis we just got from the pairing proccess (simulating a remember me login)
    // Must first create EnclaveEntry object AND decrypt prk requestis into self requestis

    // Generate prkECDHi
    const userinfo = KeyInfo.fromNativeTypeObject(decrpytedMobileData.enclaveEntry.userInfo);
    // compute ECDHI for orks that are part of bitwise (also sorted orks so keys match up with request indexes)
    const prkECDHi = await DH.generateECDHi(sortORKs(userinfo.OrkInfo).map(o => o.orkPublic).filter((_, i) => decrpytedMobileData.enclaveEntry.orksBitwise[i] == true), sessionKey.get_private_component().priv);
    const selfRequesti = await Promise.all(prkECDHi.map((dh, i) => AES.decryptDataRawOutput(base64ToBytes(decrpytedMobileData.prkRequesti[i]), dh)));

    const ee = new EnclaveEntry(
        decrpytedMobileData.enclaveEntry.username, 
        "1", 
        decrpytedMobileData.enclaveEntry.expired, 
        KeyInfo.fromNativeTypeObject(decrpytedMobileData.enclaveEntry.userInfo),
        decrpytedMobileData.enclaveEntry.orksBitwise,
        selfRequesti.map(s => bytesToBase64(s)),
        sessionKey.get_private_component().Serialize().ToBytes()
    );

    const loginFlow = new dCMKPasswordlessFlow("sess", ee, voucherURL);
    await loginFlow.ConvertRemembered();
    const f = await loginFlow.AuthenticateRemembered(null); // no gvrk
    


    console.log("Test passed");
}

