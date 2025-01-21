
import NetworkClient from "../Clients/NetworkClient.js";
import HashToPoint from "../../Cryptide/Hashing/H2P.js"
import { RandomBigInt } from "../../Cryptide/Math.js";
import dChangePassFlow from "../Flow/dChangePassFlow.js";
import { Bytes2Hex } from "../../Cryptide/Serialization.js";
import { SHA256_Digest, HMAC_forHashing } from "../../Cryptide/Hashing/Hash.js";

export default class ChangePassword{

    /**
     * @param {boolean} tokenRequested 
     */
    constructor(tokenRequested = false){
        this.tokenRequested = tokenRequested
        this.savedState = undefined;
    }

    /**
     * @param {string} username 
     * @param {string} oldPassword 
     * @param {string} newPassword 
     * @param {string} gVVK
     */
    async start(username, oldPassword, newPassword, gVVK){
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));

        const persona = 1; // this is new

        // Putting this up here to speed things up using await
        const simClient = new NetworkClient();
        const pre_keyInfo = simClient.GetKeyInfo(uid);


        //convert password to point
        const gUser = await HashToPoint(await HMAC_forHashing([persona.toString(), gVVK]));
        const gPass = await HashToPoint(oldPassword);
        const gNewPass = await HashToPoint(newPassword);
        const gBlurPass = gPass.times(r1);
        const gBlurNewPass = gNewPass.times(r2);

        // get key info
        const cmkInfo = await pre_keyInfo;

        const changePassFlow = new dChangePassFlow(cmkInfo.OrkInfo);
        const decryptedChallenges = await changePassFlow.Authenticate(uid, gBlurPass, r1);
        await changePassFlow.ChangePrism(uid, gBlurNewPass, r2, decryptedChallenges, cmkInfo.UserPublic);
        const resp = await changePassFlow.StartTest(uid, gUser, gNewPass, gVVK);

        this.savedState = {
            changePassFlow: changePassFlow
        }

        return resp;
    }

    async continue(model = null){
        if(this.savedState == undefined) throw Error("No saved state exists");
        const resp = await this.savedState.changePassFlow.ContinueTest(model);
        await this.savedState.changePassFlow.CommitPrism();
        return resp;
    }
}
