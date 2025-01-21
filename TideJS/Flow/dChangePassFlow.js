import NodeClient from "../Clients/NodeClient.js";
import { GetLi } from "../../Cryptide/Interpolation.js";
import { Point } from "../../Cryptide/index.js"
import PrismConvertResponse from "../Models/Responses/KeyAuth/Convert/PrismConvertResponse.js"
import { GetDecryptedChallenge } from "../Math/KeyAuthentication.js";
import dKeyGenerationFlow from "./dKeyGenerationFlow.js";
import { BigIntFromByteArray } from "../../Cryptide/Serialization.js";
import { mod_inv } from "../../Cryptide/Math.js";

import { SHA256_Digest } from "../../Cryptide/Hashing/Hash.js";
import TestSignIn from "../Functions-OLD/TestSignIn.js";
import OrkInfo from "../Models/Infos/OrkInfo.js";
import { Utils } from "../index.js";
//TODO: MarkParticipatingORKs

export default class dChangePassFlow{
    /**
     * 
     * @param {OrkInfo[]} cmkOrkInfo // everything about CMK orks of this user - orkID, orkURL, orkPublic 
     */
    constructor(cmkOrkInfo){
        this.cmkOrkInfo = cmkOrkInfo;
        this.savedState = undefined;
    }
    async Authenticate(uid, gBlurPass, r1){
        const clients = this.cmkOrkInfo.map(ork => new NodeClient(ork.orkURL)) // create node clients

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map(client => client.PrismConvert(uid, gBlurPass, true));
        const settledPromises = await Promise.allSettled(pre_ConvertResponses);// determine which promises were fulfilled

        //TODO: //const bitwise = MarkParticipatingORKs(settledPromises);
        var activeOrks = []
        settledPromises.forEach((promise, i) => {
            if(promise.status === "fulfilled") activeOrks.push(this.cmkOrkInfo[i]) // create new ork list on orks which replied
        }); 
        if(activeOrks.length < Utils.Threshold){
            // @ts-ignore
            if(settledPromises.filter(promise => promise.status === "rejected").some(promise => promise.reason === "Too many attempts")) throw new Error("Too many attempts")
            else throw new Error("CMK Orks for this account are down");
        } 
        this.cmkOrkInfo = activeOrks;

        // Generate lis for CMKOrks based on the ones that replied
        const ids = this.cmkOrkInfo.map(ork => BigInt(ork.orkID)); // create lis for all orks that responded
        const lis = ids.map(id => GetLi(id, ids, Point.order));

        /**@type {PrismConvertResponse[]} */
        // @ts-ignore
        const PrismConvertResponses = settledPromises.filter(promise => promise.status === "fulfilled").map(promise => promise.value); // .value will exist here as we have filtered the responses above

        this.aState = {
            //TODO: //bitwise: bitwise
        }

        return await GetDecryptedChallenge(PrismConvertResponses, lis, this.cmkOrkInfo.map(c => c.orkPublic), r1);
    }
    /**
     * @param {string} uid 
     * @param {Point} gBlurNewPass 
     * @param {bigint} r2 
     * @param {string[]} decryptedChallenges 
     * @param {Point} userPublic
     * @returns 
     */
    async ChangePrism(uid, gBlurNewPass, r2, decryptedChallenges, userPublic){
        if(this.aState == undefined) throw Error("aState is undefined");

        const prismGenFlow = new dKeyGenerationFlow(uid, this.cmkOrkInfo);
        const prismGenShardData = await prismGenFlow.UpdateShard(decryptedChallenges, gBlurNewPass, this.aState.bitwise, userPublic);  // GenShard

        const gNewPassPRISM = prismGenShardData.gMultiplied[0].times(mod_inv(r2));
        const gNewPRISMAuth = Point.g.times(BigIntFromByteArray(await SHA256_Digest(gNewPassPRISM.toArray())));

        await prismGenFlow.SetShard(gNewPRISMAuth, "Prism", true);  // async SendShard with userExists set to TRUE
        this.savedState = {
            genFlow: prismGenFlow
        };
    }
    /**
     * @param {string} uid 
     * @param {Point} gUser 
     * @param {Point} gNewPass 
     * @param {string} gVVK 
     * @returns 
     */
    async StartTest(uid, gUser, gNewPass, gVVK){
        const testSignIn = new TestSignIn(this.cmkOrkInfo, undefined, true, true, false); // priority to find VUID here
        this.testSignInFlow = testSignIn;
        return await testSignIn.start(uid, gUser, gNewPass, gVVK); // need to get vuid here somehow
    }
    async ContinueTest(model = null){
        if(this.testSignInFlow == undefined) throw Error('Test sign in flow does not exist');
        return await this.testSignInFlow.continue(model);
    }
    async CommitPrism(){
        if(this.savedState == undefined) throw Error("No saved state")
        await this.savedState.genFlow.Commit("Prism");
    }
}