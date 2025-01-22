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

import { HMAC_forHashing, SHA256_Digest } from "../Cryptide/Hashing/Hash.js";
import { BigIntToByteArray, Bytes2Hex, bytesToBase64 } from "../Cryptide/Serialization.js";
import { RandomBigInt } from "../Cryptide/Math.js";
import NetworkClient from "../Clients/NetworkClient.js";
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow-OLD.js";
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js";
import { Point } from "../Cryptide/index.js";
import HashToPoint from "../Cryptide/Hashing/H2P.js"
import TestSignIn from "./TestSignIn.js";
import OrkInfo from "../Models/Infos/OrkInfo.js";

export default class SignIn {

    constructor(gVVK, enclaveRequest = null) {

        // Check enclaveRequest contains correct fields if provided.
        if (enclaveRequest !== null) {
            if (!Object.hasOwn(enclaveRequest, 'refreshToken')) { throw Error("Enclave Request does not include refreshToken field") }
            if (!Object.hasOwn(enclaveRequest, 'getUserInfoFirst')) { throw Error("Enclave Request does not include getUserInfoFirst field") }
            if(enclaveRequest.customModel !== undefined){
                if (!Object.hasOwn(enclaveRequest.customModel, 'name')) { throw Error("Custom Model does not include name field") }
                if (!Object.hasOwn(enclaveRequest.customModel, 'data')) { throw Error("Custom Model does not include data field") }
            }
        }
        
        this.enclaveRequest = enclaveRequest
        
        this.authFlow = undefined
        this.cvkInfo = undefined
        this.cvkExists = undefined
        this.gVVK = gVVK
        this.createCVKState = undefined
    }

    /**
     * @param {string} username 
     * @param {string} password 
     */
    async start(username, password) {
        const startTime = BigInt(Math.floor(Date.now() / 1000));
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));

        // Putting this up here to speed things up using await
        const simClient = new NetworkClient();
        const pre_keyInfo = simClient.GetKeyInfo(uid);

        const persona = 1; // this is new

        const gUser = await HashToPoint(await HMAC_forHashing([persona.toString(), this.gVVK]));
        const gBlurUser = gUser.times(r2);
        //convert password to point
        const gPass = await HashToPoint(password);
        const gBlurPass = gPass.times(r1);

        // get key info
        const cmkInfo = await pre_keyInfo;

        const authFlow = new dKeyAuthenticationFlow(cmkInfo.OrkInfo, true, true, this.enclaveRequest?.refreshToken);
        const convertData = await authFlow.Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, cmkInfo.UserPublic);

        try{
            this.cvkInfo = await simClient.GetKeyInfo(convertData.VUID);
            this.cvkExists = true;
            this.authFlow = authFlow;
        }catch{
            // key for VUID was not found
            this.cvkExists = false;
            this.createCVKState = {
                uid: uid,
                gUser: gUser,
                gPass: gPass,
                cmkOrkInfo: cmkInfo.OrkInfo,
                cvkOrkInfo: cmkInfo.OrkInfo // same cmkOrkInfo as cvk for now HERE
            }
            return await this.createCVK(convertData.VUID, convertData.gCMKAuth, cmkInfo.OrkInfo); // cvk orks are the same as cmk orks for now HERE
        }

        return {
            ok: true,
            dataType: "userData",
            newAccount: false,
            publicKey: this.cvkInfo.UserPublic.toBase64(),
            uid: convertData.VUID
        };
    }

    /**
     * @param {object} model 
    */
    async continue(model=null){
        if(this.cvkExists == undefined) throw Error("SignIn methods implemented improperly");
        if(this.cvkExists) return this.continueSignIn(model);
        else if(this.cvkExists == false) return this.commitCVK(model);
        else throw Error("Strange error occured")
    }

    /**
     * CMK exists for this user but no CVK for this vendor. Let's create one.
     * @param {string} VUID 
     * @param {Point} gCMKAuth
     * @param {OrkInfo[]} cvkOrkInfo 
     */
    async createCVK(VUID, gCMKAuth, cvkOrkInfo){
        const cvkGenFlow = new dKeyGenerationFlow(VUID, cvkOrkInfo);
        const cvkGenShardData = await cvkGenFlow.GenShard(1, []);
        await cvkGenFlow.SetShard(gCMKAuth, "CVK");
        this.createCVKState.cvkGenFlow = cvkGenFlow;

        return {
            ok: true,
            dataType: "userData",
            newAccount: true,
            publicKey: cvkGenShardData.gK1.toBase64(),
            uid: VUID
        };
    }

    async continueSignIn(model_p=null){
        if(!this.authFlow) throw Error("No authflow/convertData available in saved state"); // use this to determine not only if savedState exists, but also for VUID (from createCVK process)

        const model = this.enclaveRequest.customModel === undefined ? model_p : this.enclaveRequest.customModel;

        this.authFlow.CVKorks = this.cvkInfo.OrkInfo;
        await this.authFlow.Authenticate_and_PreSignInCVK(model === null ? null : model.Name);
        const {jwt, modelSig, sessKey} = await this.authFlow.SignInCVK(model, this.gVVK);
        const sessionDataJSON = {
            Private: bytesToBase64(BigIntToByteArray(sessKey)),
            JWT: jwt
        };
        window.localStorage.setItem("TideSessionData", JSON.stringify(sessionDataJSON)); // store sessKey on successful login as a base64 encoding of the number
        return {
            ok: true,
            dataType: "completed", 
            TideJWT: jwt, 
            modelSig: modelSig
        };
    }

    async commitCVK(model=null){

        if(!this.createCVKState) throw Error("No Create CVK State available in saved state"); // use this to determine not only if savedState exists, but also for VUID (from createCVK process)

        const testSignIn = new TestSignIn(this.createCVKState.cmkOrkInfo, this.createCVKState.cvkOrkInfo, true, false, true); // send cmkOrkInfo twice as there is no vendor selection of CVK orks yet
        await testSignIn.start(this.createCVKState.uid, this.createCVKState.gUser, this.createCVKState.gPass, this.gVVK);

        const resp = await testSignIn.continue(model);
        
        // test dDecrypt() ?

        await this.createCVKState.cvkGenFlow.Commit("CVK");

        return resp;
    }
}
