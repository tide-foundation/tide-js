import OrkInfo from "../Models/Infos/OrkInfo.js";
import HashToPoint from "../Cryptide/Hashing/H2P.js";
import { HMAC_forHashing } from "../Cryptide/Hashing/Hash.js";
import { Serialization } from "../Cryptide/index.js";
import { Math } from "../Cryptide/index.js";
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js";
import dAccountRecoveryFlow from "../Flow/dAccountRecoveryFlow.js";
import { CurrentTime, Max } from "../Tools/Utils.js";
import EnclaveEntry from "../Models/EnclaveEntry.js";
import { CreateGPrismAuth } from "../Cryptide/Math.js";
import KeyInfo from "../Models/Infos/KeyInfo.js";
import PollingClient from "../Clients/PollingClient.js";
import { Point } from "../Cryptide/Ed25519.js";


export async function EmailRecovery(){
    var orks;

    const user = Date.now().toString();
    const persona = "1";
    const emails = ["testEmail1@doge.com"]
    const password = "pass";

    const gPass =  await HashToPoint(password);
    const uid = await Serialization.GetUID(user);
    const sessKey = Math.GenSessKey();
    const gSessKey = Math.GetPublic(sessKey);
    let GK;

    const create = async() => {
        // create account first
        const purpose = "NEW";
        const {reservationConfirmation, activeOrks} = (await dKeyGenerationFlow.ReserveUID(uid, "http://localhost:3000/voucher/new", gSessKey));
        orks = activeOrks.slice(0, Max);
        const genFlow = new dKeyGenerationFlow(uid, "", orks, sessKey, gSessKey, purpose, "http://localhost:3000/voucher/new", emails);
        const {gMultiplied, gK} = await genFlow.GenShard(2, [null, gPass], reservationConfirmation); // auths can be null if purpose is "new", for now...
        const gPrismAuth = await CreateGPrismAuth(gMultiplied[1]);
        GK = gK;
        await genFlow.SetShard(gPrismAuth, "CMK");
        await genFlow.Commit();
    }

    const recover = async() => {
        const newPassword = "pass1";
        const newgPass = await HashToPoint(newPassword);
        const homeOrkUrl = "http://host.docker.internal:1001";
        const pollingClient = new PollingClient(homeOrkUrl);
        const signal = new AbortController().signal;

        const recoveryFlow = new dAccountRecoveryFlow(uid, orks, sessKey, gSessKey, "http://localhost:3000/voucher/new");
        const { channelId, status: startAccountRecoveryStatus } = await recoveryFlow.StartAccountRecovery(homeOrkUrl, pollingClient, signal);

        await recoveryFlow.RetrieveEmailAuths(channelId, () => {}, pollingClient, signal);
        await recoveryFlow.GenerateNewPrism(GK, newgPass, Point.BASE);
    }

    await create();
    await recover();

    console.log("EmailRecovery TEST SUCCESSFUL");
}