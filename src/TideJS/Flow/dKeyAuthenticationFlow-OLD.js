// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

import NodeClient from "../Clients/NodeClient.js";
import { Point } from "../../Cryptide/index.js"
import { CmkConvertReply, PreSignInCVKReply, PrismConvertReply, SignInCVKReply } from "../Math/KeyAuthentication.js";
import { GetLi } from "../../Cryptide/Interpolation.js";
import PrismConvertResponse from "../Models/Responses/KeyAuth/Convert/PrismConvertResponse.js";
import OrkInfo from "../Models/Infos/OrkInfo.js";
import { TideJWT } from "../index.js";

export default class dKeyAuthenticationFlow{
    /**
     * @param {OrkInfo[]} CMKorks 
     * @param {boolean} cmkCommitted
     * @param {boolean} cvkCommitted
     * @param {boolean} prismCommitted
     * @param {boolean} tokenRequested
     */
    constructor(CMKorks, cmkCommitted, cvkCommitted, prismCommitted, tokenRequested = false) {
        /**
         * @type {OrkInfo[]}  // everything about CMK orks of this user - orkID, orkURL, orkPublic
         */
        this.CMKorks = CMKorks;
        /**
         * @type {OrkInfo[]}
         */
        this.CVKorks = CMKorks;
        this.cmkCommitted = cmkCommitted
        this.cvkCommitted = cvkCommitted
        this.prismCommitted = prismCommitted

        this.tokenRequested = tokenRequested

        this.cState = undefined;
        this.aState = undefined;
}

    /**
     * 
     * @param {string} uid 
     * @param {Point} gBlurUser 
     * @param {Point} gBlurPass 
     * @param {bigint} r1 
     * @param {bigint} r2
     * @param {bigint} startTime
     * @param {Point} gCMK
     */
    async Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, gCMK){
        const clients = this.CMKorks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        // Here we also find out which ORKs are up
        const pre_ConvertResponses = clients.map((client, i) => client.Convert(i, uid, gBlurUser, gBlurPass, this.cmkCommitted, this.prismCommitted));
        const unsortedConvertResponses = await PromiseRace(pre_ConvertResponses, "CMK");   //// HEY ! UPDATE THIS

        /**@type {{index: number, CMKConvertResponse: string, PrismConvertResponse: PrismConvertResponse}[]} */
        const ConvertResponses = unsortedConvertResponses.sort((a, b) => a.index - b.index);
        //remove CMKOrks that are not at indexes in convert responses
        this.CMKorks = this.CMKorks.filter((_, i) => !ConvertResponses.every(resp => resp.index != i)); // if ork at index 0 does not include a response with index 0, remove ork

        // Generate lis for CMKOrks based on the ones that replied
        const ids = this.CMKorks.map(ork => BigInt(ork.orkID)); // create lis for all orks that responded
        const lis = ids.map(id => GetLi(id, ids, Point.order));

        
        const {prismAuthis, deltaTime, decChallengei} = await PrismConvertReply(ConvertResponses.map(c => c.PrismConvertResponse), lis, this.CMKorks.map(c => c.orkPublic), r1, startTime);

        this.cState = {
            uid: uid,
            decChallengei: decChallengei,
            ... await CmkConvertReply(uid, ConvertResponses.map(c => c.CMKConvertResponse), lis, prismAuthis, gCMK, r2, deltaTime)
        }
        return{
            VUID: this.cState.VUID,
            gCMKAuth: this.cState.data_for_PreSignInCVK.gCMKAuth
        }
    }

    /**
     * @param {string} modelName
     */
    async Authenticate_and_PreSignInCVK(modelName=null){
        if(this.cState == undefined) throw Error("Convert State is undefined");
        const cmkClients = this.CMKorks.map(ork => new NodeClient(ork.orkURL))
        // TODO: Once sim client ceases to exist, fill in this.CVKorks here by quering a cmkork
        const cvkClients = this.CVKorks.map(ork => new NodeClient(ork.orkURL))

        const pre_encSig = cmkClients.map((client, i) => client.Authenticate(this.cState.uid, this.cState.decChallengei[i], this.cState.encAuthRequests[i], this.cmkCommitted, 
            this.prismCommitted))

        const encSig = await Promise.all(pre_encSig);

        // Here we also find out which ORKs are up
        const pre_encGRData = cvkClients.map((client, i) => client.PreSignInCVK(i, this.cState.VUID, this.cState.gSessKeyPub, this.tokenRequested, modelName, this.cvkCommitted));
        const unsorted_encGRData = await PromiseRace(pre_encGRData, "CVK");  //// HEY ! UPDATE THIS

        /**@type {{index: number, encGRData: string}[]} */
        const encGRData = unsorted_encGRData.sort((a, b) => a.index - b.index);
        //remove CMKOrks that are not at indexes in convert responses
        this.CVKorks = this.CVKorks.filter((_, i) => !encGRData.every(resp => resp.index != i)); // if ork at index 0 does not include a response with index 0, remove ork

        // Generate lis for CVKOrks based on the ones that replied
        const vids = this.CVKorks.map(ork => BigInt(ork.orkID)); 
        const vlis = vids.map(id => GetLi(id, vids, Point.order));

        this.aState = {
            uid: this.cState.uid,
            VUID: this.cState.VUID,
            timestamp2: this.cState.timestamp2,
            gRMul: this.cState.data_for_PreSignInCVK.gRMul,
            sessKey: this.cState.data_for_PreSignInCVK.SessKey,
            ... await PreSignInCVKReply(encSig, encGRData.map(a => a.encGRData), this.cState.data_for_PreSignInCVK, this.CVKorks.map(o => o.orkPublic)),
            gSessKeyPub: this.cState.gSessKeyPub,
            'vlis' : vlis
        };
        this.cState = undefined; // save on memory?
    }

    /**
     * @param {object} model
     * @param {string} gVVK
     */
    async SignInCVK(model=null, gVVK=null){
        if(this.aState == undefined) throw Error("Authenticate and PreSignIn state does not exist");
        const cvkClients = this.CVKorks.map(ork => new NodeClient(ork.orkURL))

        const pre_encSigs = cvkClients.map((client, i) => client.SignInCVK(this.aState.VUID, this.aState.timestamp2, this.aState.gRMul, this.aState.S, this.aState.gCVKRi, this.aState.vlis[i], 
            this.aState.gBlindH, model, gVVK, this.cvkCommitted));
        const encSigs = await Promise.all(pre_encSigs);

        const signInReply = await SignInCVKReply(encSigs, this.aState.gCVKRi, this.aState.ECDHi, this.aState.vlis, this.tokenRequested, model);
        
        const expTime = this.aState.timestamp2 + 600n;

        let jwt = null;
        if(this.tokenRequested){
            const unsigned = TideJWT.new(this.aState.VUID, expTime, this.aState.gSessKeyPub, gVVK);
            jwt = TideJWT.addSignature(unsigned, signInReply.CVKS, this.aState.gCVKRi[0]); // ok to access gCVKRi[0] as the jwt will always be signed first (index 0)
        }
        return {jwt: jwt, modelSig: signInReply.modelSig, sessKey: this.aState.sessKey}
    }
}