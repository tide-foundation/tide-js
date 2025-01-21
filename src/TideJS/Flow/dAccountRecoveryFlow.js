import NodeClient from "../Clients/NodeClient.js";
//TODO: //import { MarkParticipatingORKs } from "../Tools/Utils.js";
import OrkInfo from "../Models/Infos/OrkInfo.js";
import { CurrentTime, WaitForNumberofORKs } from "../Tools/Utils.js";
import { dKeyGenerationFlow } from "../index.js";
import Point from "../../Cryptide/Ed25519.js";
import { ElGamal } from "../../Cryptide/index.js";
import { bytesToBase64 } from "../../Cryptide/Serialization.js";
import { CreateGPrismAuth } from "../../Cryptide/Math.js";
import dCMKPasswordFlow from "./AuthenticationFlows/dCMKPasswordFlow.js";
import VoucherFlow from "./VoucherFlows/VoucherFlow.js";
import KeyInfo from "../Models/Infos/KeyInfo.js";
export default class dAccountRecoveryFlow {
    /**
     * @param {string} uid
     * @param {OrkInfo[]} orks
     * @param {Uint8Array} sessKey
     * @param {Point} gSessKey
     * @param {string} voucherURL
     */
    constructor(uid, orks, sessKey, gSessKey, voucherURL) {
        // NOTE: User will only EVER click threshold orks, so for keyGen all of those 14 orks MUST be up. An ork cannot go
        // down between email sending and key recreation. Otherwise process must start again.
        this.uid = uid;
        this.orks = orks;
        this.sessKey = sessKey;
        this.gSessKey = gSessKey;
        this.voucherURL = voucherURL;

        this.rState = undefined;
    }

    async StartAccountRecovery(homeOrkUrl, pollingClient, signal){
        const channelId = await pollingClient.EstablishHttpTunnel(this.uid, this.orks.map(o => o.orkID));
        const clients = this.orks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "updateaccount");
        const {vouchers} = await voucherFlow.GetVouchers();

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map((client, i) => client.RecoverAccount(i, this.uid, this.gSessKey, channelId, homeOrkUrl, vouchers.toORK(i)));
        await WaitForNumberofORKs(this.orks.slice(), pre_ConvertResponses, "CMK", null, null, null, 30000); // we DON'T want to modify the orks array for this specific flow - we need it in full for the key gen flow below
        
        if ( signal.aborted) {
            return { status: "cancelled" }
        }

        return {channelId}
    }

    /**
     * @returns 
     */
    async RetrieveEmailAuths(
        channelId, 
        progressTrackerCallback, 
        pollingClient, 
        signal) {
        // Start the long polling requests
        const { encRequests, bitwise, status } = await pollingClient.pollServer(channelId, progressTrackerCallback, signal);

        if ( status === "recovered"){
            const pre_decData = encRequests.map(async (request) => bytesToBase64(await ElGamal.decryptData(request, this.sessKey)));
            const selfRequesti = await Promise.all(pre_decData);
    
            const expiry = CurrentTime() + 3580;
    
            this.rState = {
                bitwise,
                selfRequesti,
                expiry,
            }
        }

        // return the status, "recovered" or "cancelled"
        return { status };
    }

    /**
     * @param {Point} currentUserPublic
     * @param {Point} newGPass
     * @param {Point} gVRK
     */
    async GenerateNewPrism(currentUserPublic, newGPass, gVRK) {
        if (this.rState == undefined) throw Error("RState must be defined first");

        if (this.rState.expiry < CurrentTime()) throw Error("Took too long to open emails.")

        const newPrismFlow = new dKeyGenerationFlow(
            this.uid,
            gVRK.toBase64(),
            this.orks,
            this.sessKey,
            this.gSessKey,
            "RECOVER",
            this.voucherURL,
            null,
            this.rState.bitwise,
            this.rState.selfRequesti,
            currentUserPublic,
            this.rState.expiry
        );
        const { gMultiplied } = await newPrismFlow.GenShard(1, [newGPass]);
        const newGPrismAuth = await CreateGPrismAuth(gMultiplied[0]);
        const keyM = await newPrismFlow.SetShard(newGPrismAuth, "Prism");
        const keyInfo = new KeyInfo(this.uid, currentUserPublic, keyM, this.orks);

        // test new account
        const testAuthFlow = new dCMKPasswordFlow(keyInfo, "TEST SESSION", true, false, this.voucherURL);
        await testAuthFlow.Convert(this.sessKey, this.gSessKey, newGPass, currentUserPublic, false);
        await testAuthFlow.Authenticate(gVRK);

        await newPrismFlow.Commit();
    }

    async CleanUpRecoverySession(channelId){
        const homeOrkUrl = window.location.origin;
        const homeOrkClient = new NodeClient(homeOrkUrl);

        await homeOrkClient.FinalizeAccountRecovery(this.uid, channelId);
    }
}