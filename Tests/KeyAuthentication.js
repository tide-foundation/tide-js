import OrkInfo from "../Models/Infos/OrkInfo.js";
import HashToPoint from "../Cryptide/Hashing/H2P.js";
import { Serialization } from "../Cryptide/index.js";
import { HMAC_forHashing } from "../Cryptide/Hashing/Hash.js";
import dCMKPasswordFlow from "../Flow/AuthenticationFlows/dCMKPasswordFlow.js";
import dCMKPasswordlessFlow from "../Flow/AuthenticationFlows/dCMKPasswordlessFlow.js";
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js";
import { Math } from "../Cryptide/index.js";
import { CreateGPrismAuth, GetPublic } from "../Cryptide/Math.js";
import EnclaveEntry from "../Models/EnclaveEntry.js";
import KeyInfo from "../Models/Infos/KeyInfo.js";
import NetworkClient from "../Clients/NetworkClient.js";
import { Max } from "../Tools/Utils.js";

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
            const keyInfo = await new NetworkClient("http://host.docker.internal:1001").GetKeyInfo(uid);
            const dAuthFlow = new dCMKPasswordFlow(keyInfo, sessID, true, true, "http://host.docker.internal:3000/voucher/new");
            await dAuthFlow.Convert(sessKey, gSessKey, gPass, GK, true);
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
            const keyInfo = await new NetworkClient("http://localhost:1001").GetKeyInfo(uid);
            const dAuthFlow = new dCMKPasswordFlow(keyInfo, sessID, true, true, "http://localhost:3000/voucher/new");
            await dAuthFlow.Convert(sessKey, gSessKey, gPass, GK, true);
            const {bitwise, expired, selfRequesti} = await dAuthFlow.Authenticate(gSessKey); // gVRK can be anything for testing
            const userInfo = new KeyInfo(uid, GK, keyInfo.UserM, orks);
            const auth = new EnclaveEntry(user, "1", BigInt(expired), userInfo, bitwise, selfRequesti, sessKey);
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