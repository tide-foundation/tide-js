import { SimulatorFlow, Utils } from "../index.js";
import { CreateGPrismAuth, GenSessKey, GetPublic, RandomBigInt } from "../Cryptide/Math.js";
import { base64ToBytes, BigIntToByteArray, Bytes2Hex, bytesToBase64, GetUID, Hex2Bytes, StringToUint8Array } from "../Cryptide/Serialization.js";
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js";
import OrkInfo from "../Models/Infos/OrkInfo.js";
import HashToPoint from "../Cryptide/Hashing/H2P.js";
import { HMAC_forHashing } from "../Cryptide/Hashing/Hash.js";
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow-OLD.js";
import dCMKPasswordFlow from "../Flow/AuthenticationFlows/dCMKPasswordFlow.js";
import EnclaveEntry from "../Models/EnclaveEntry.js";
import KeyInfo from "../Models/Infos/KeyInfo.js";
import NetworkClient from "../Clients/NetworkClient.js";
import AuthRequest from "../Models/AuthRequest.js";
import { CurrentTime, Max } from "../Tools/Utils.js";
import { EdDSA, Point } from "../Cryptide/index.js";
import dTestVVKSigningFlow from "../Flow/SigningFlows/dTestVVkSigningFlow.js";
import BaseTideRequest from "../Models/BaseSignRequest.js";
import dVVKSigningFlow from "../Flow/SigningFlows/dVVKSigningFlow.js";
import { Ed25519PrivateComponent, Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import { CreateAuthorizerPackage, CreateVRKPackage } from "../Cryptide/TideMemoryObjects.js";

export async function NewCMK_NewPRISM(){
    var orks;
    let i = 0;
    while(i < 1){
        const user = Date.now().toString();
        const password = "pass";
        const emails = ["testEmail1@doge.com"]

        const uid = await GetUID(user);
        const sessKey = GenSessKey();
        const gSessKey = GetPublic(sessKey);
        const purpose = "NEW";

        const VRK = BigInt(123456789);
        const gVRK = GetPublic(VRK);

        const {reservationConfirmation, activeOrks} = (await dKeyGenerationFlow.ReserveUID(uid, "http://localhost:3000/voucher/new", gSessKey));
        orks = activeOrks.slice(0, Max);
        const genFlow = new dKeyGenerationFlow(uid, gVRK.toBase64(), orks, sessKey, gSessKey, purpose, "http://localhost:3000/voucher/new", emails);
        await genFlow.GenShard(2, [null], reservationConfirmation); // auths can be null if purpose is "new", for now...
        await genFlow.SetShard(gSessKey.toBase64(), "CMK"); // we aren't testing the auth point, can be anything here
        await genFlow.Commit();

        console.log("NewCMK_NewPRISM TEST SUCCESSFUL: " + i)
        i++;
    }

    

    // note: i'm not putting everything in a try catch as i want to see which line at which file fails
}

export async function ExistingCMK_NewPRISM(){
    // basically the change pass flow
    var orks;
    let i = 0;
    while(i < 1){

        const user = Date.now().toString();
        const emails = ["testEmail1@doge.com"]

        const password = "pass";
        const gPass =  await HashToPoint(password);
        const uid = await GetUID(user);
        const sessKey = GenSessKey();
        const gSessKey = GetPublic(sessKey);
        const VRK = BigInt(123456789);
        const gVRK = GetPublic(VRK);
        let GK;

        const create = async () => {
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

        const getAuth = async() => {
            const keyInfo = await new NetworkClient("http://localhost:1001").GetKeyInfo(uid);
            const keyAuthFlow = new dCMKPasswordFlow(keyInfo, "", true, true, "http://localhost:3000/voucher/new"); // needs these orks 
            const {bitwise, expired, selfRequesti} = await keyAuthFlow.ConvertPassword(sessKey, gSessKey, gPass);
            return {bitwise, expired, selfRequesti};
        }

        const newPrism = async (bitwise, expired, selfRequesti) => {
            const purpose = "RESET";
            const newPassword = "pass1";
            const newgPass = await HashToPoint(newPassword);
            const genFlow = new dKeyGenerationFlow(uid, gVRK.toBase64(), orks, sessKey, gSessKey, purpose, "http://localhost:3000/voucher/new", null, bitwise, selfRequesti, GK, expired); // this flow
            await genFlow.GenShard(1, [newgPass]);
            await genFlow.SetShard(gSessKey.toBase64(), "Prism"); // we aren't testing the auth point, can be anything here
            await genFlow.Commit();
        }
        
        await create();
        const {bitwise, expired, selfRequesti} = await getAuth();
        await newPrism(bitwise, expired, selfRequesti);

        console.log("ExistingCMK_NewPRISM TEST SUCCESSFUL: " + i);
        i++;
    }
}

// Assuming orks are not checking that each gVRK has funds attached to it
export async function NewVVK(){
    const simClient = new NetworkClient();
    const availableOrks = (await simClient.FindReservers("blah"));
    const orks = (await SimulatorFlow.FilterInactiveOrks(availableOrks)).slice(0, Max);

    let i = 0;
    while(i < 1){
        const sessKey = GenSessKey();
        const gSessKey = GetPublic(sessKey);

        const VRK = BigInt(123456789);
        const gVRK = GetPublic(VRK);
        const VVKid = "VendorID12345";
        const auth = new AuthRequest(VVKid, "NEW", gSessKey.toBase64(), BigInt(CurrentTime() + 30))
        const authSig = await EdDSA.sign(auth.toString(), VRK);

        // Midgard can replace this line
        const vrkPackage = CreateVRKPackage(new Ed25519PublicComponent(gVRK), Utils.CurrentTime() + 300);
        const authorizerPackage = CreateAuthorizerPackage("VRK:1", ["TestInit:1", "AccessTokenInit:1", "RotateVRK:1"], vrkPackage);
        console.log("AUTHORIZER: " + Bytes2Hex(authorizerPackage));

        const genFlow = new dKeyGenerationFlow(VVKid, gVRK.toBase64(), orks, sessKey, gSessKey, "NEW", "http://localhost:3000/voucher/new");
        const {gK} = await genFlow.GenVVKShard(auth, authSig);
        const signAuth = await genFlow.SetShard(Bytes2Hex(authorizerPackage), "VVK");

        const testSignFlow = new dTestVVKSigningFlow(VVKid, gK, orks, sessKey, gSessKey, VRK, authorizerPackage, signAuth.VRK_SIGNATURE_TO_STORE,  "http://localhost:3000/voucher/new");
        await testSignFlow.start();
        
        const req = new BaseTideRequest("AccessTokenInit", "1", "VRK:1", StringToUint8Array(""));
        const sig = base64ToBytes(await EdDSA.sign(await req.dataToAuthorize(), VRK));
        req.addAuthorization(sig);
        req.addAuthorizer(authorizerPackage);
        req.addAuthorizerCertificate(signAuth.VRK_SIGNATURE_TO_STORE);

        const signFlow = new dVVKSigningFlow(VVKid, gK, orks, sessKey, gSessKey, "http://localhost:3000/voucher/new");
        await signFlow.start(req, true);

        await genFlow.Commit();

        console.log("vrk raw: " + new Ed25519PrivateComponent(VRK).Serialize().ToString());
        console.log("authorizer cert: " + bytesToBase64(signAuth.VRK_SIGNATURE_TO_STORE))

        console.log("NewVVK TEST SUCCESSFUL: " + i);
        i++;
    }

}

export async function HealPrism(){
    // basically the change pass flow
    var orks;

    let i = 0;
    while(i < 1){

        const user = Date.now().toString();
        const emails = ["testEmail1@doge.com"]

        const password = "pass";
        const gPass =  await HashToPoint(password);
        const uid = await GetUID(user);
        const sessKey = GenSessKey();
        const gSessKey = GetPublic(sessKey);
        const VRK = BigInt(123456789);
        const gVRK = GetPublic(VRK);
        let GK;

        const create = async () => {
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

        const getAuth = async() => {
            const keyInfo = await new NetworkClient("http://localhost:1001").GetKeyInfo(uid);
            const keyAuthFlow = new dCMKPasswordFlow(keyInfo, "", true, true, "http://localhost:3000/voucher/new"); // needs these orks 
            const {bitwise, expired, selfRequesti} = await keyAuthFlow.ConvertPassword(sessKey, gSessKey, gPass);
            return {bitwise, expired, selfRequesti};
        }

        const newPrism = async (bitwise, expired, selfRequesti) => {
            const purpose = "RESET";
            const newPassword = "pass1";
            const newgPass = await HashToPoint(newPassword);
            const genFlow = new dKeyGenerationFlow(uid, gVRK.toBase64(), orks, sessKey, gSessKey, purpose, "http://localhost:3000/voucher/new", null, bitwise, selfRequesti, GK, expired); // this flow
            const {gMultiplied, gK} = await genFlow.GenShard(1, [newgPass]);
            const gPrismAuth = await CreateGPrismAuth(gMultiplied[0]);
            await genFlow.SetShard(gPrismAuth.toBase64(), "Prism"); 
            await genFlow.Commit();
            return newgPass;
        }

        const authTest = async(newgPass) => {
            const sessKey = GenSessKey();
            const gSessKey = GetPublic(sessKey);
            const keyInfo = await new NetworkClient("http://localhost:1001").GetKeyInfo(uid);
            const dAuthFlow = new dCMKPasswordFlow(keyInfo, "123ID", true, true, "http://localhost:3000/voucher/new");
            await dAuthFlow.Convert(sessKey, gSessKey, newgPass, GK, true);
            const {bitwise, expired, selfRequesti} = await dAuthFlow.Authenticate(gSessKey); // gVRK can be anything for testing
            return selfRequesti;
        }
        
        await create();
        await authTest(gPass); // first auth test to get key healing to start
        window.alert("Shut 2 orks down now.")
        const {bitwise, expired, selfRequesti} = await getAuth();
        console.log("auth test 1 worked");
        const newgPass = await newPrism(bitwise, expired, selfRequesti);
        await authTest(newgPass); // first auth test to get key healing to start
        console.log("auth test 2 worked");
        window.alert("Turn on 1 ork now.")
        await authTest(newgPass); // hopefully heal is done by now
        console.log("auth test 3 worked");
        const delay = () => new Promise(res => setTimeout(res, 2000)); // wait 2s
        await delay();
        window.alert("Turn on the other ork now.")
        await authTest(newgPass); // hopefully heal is done by now
        console.log("auth test 4 worked");
        await delay();
        const selfRs = await authTest(newgPass); // hopefully heal is done by now
        console.log("auth test 5 worked");
        const worked = selfRs.length == Max;

        console.log("Test successful: " + worked + ". Best to set Threshold:Max to 3:5 for most accurate results. Check ork logs to see if key heal was successful.")
        console.log("HealPrism TEST SUCCESSFUL: " + i);
        i++;
    }
}