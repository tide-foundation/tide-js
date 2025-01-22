import NetworkClient from "../Clients/NetworkClient.js";
import { RandomBigInt } from "../Cryptide/Math.js";
import { Point } from "../Cryptide/index.js";
import { Bytes2Hex } from "../Cryptide/Serialization.js";
import { SHA256_Digest } from "../Cryptide/Hashing/Hash.js";
import dAccountRecoveryFlow from "../Flow/dAccountRecoveryFlow.js";
import NodeClient from "../Clients/NodeClient.js";
export default class RecoverAccount {

    constructor() {
        this.savedState = undefined;
    }

    /**
     * @param {string} username 
     */
    async start(username) {

        // Generate session keys
        const sessKey = RandomBigInt();
        const gSessKey = Point.g.times(sessKey);

        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));

        // Putting this up here to speed things up using await
        const simClient = new NetworkClient();
        const pre_keyInfo = simClient.GetKeyInfo(uid);


        // get key info
        const cmkInfo = await pre_keyInfo;

        const recoverAccountFlow = new dAccountRecoveryFlow(uid, cmkInfo.OrkInfo);

        const mIdOrkArray = cmkInfo.OrkInfo.map(ork => ork.orkID);

        // Initialise long polling session with home ork
        const homeOrkUrl = window.location.origin
        const homeOrkClient = new NodeClient(homeOrkUrl);
        const channelId = await homeOrkClient.EstablishHttpTunnel(uid, mIdOrkArray);

        await recoverAccountFlow.RetrieveEmailAuths(channelId, gSessKey);

        this.savedState = {
            recoverAccountFlow: recoverAccountFlow
        }


        // Start the long polling requests
        // move the loop out here, so we can notify the status to the user.
        const encRequest = await homeOrkClient.pollServer(channelId);

        // Verify the encryptedRequests
        // handle different statuses not just completions
        if (encRequest.length <= 0) {
            console.log("NO REQUESTS")
            return;
        }

        const pre_decData = encRequest.map(async (request) => await ElGamal.decryptData(request, sessKey));
        const decData = await Promise.all(pre_decData);


        // const auth = [selfRequest...]

    }

}