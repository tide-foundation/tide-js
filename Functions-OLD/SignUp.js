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

import { Point } from "../Cryptide/index.js";
import { SHA256_Digest, SHA512_Digest, HMAC_forHashing } from "../Cryptide/Hashing/Hash.js";
import { BigIntFromByteArray, Bytes2Hex, } from "../Cryptide/Serialization.js";
import { mod, mod_inv, RandomBigInt } from "../Cryptide/Math.js";
import dKeyGenerationFlow from "../Flow/dKeyGenerationFlow.js";
import TestSignIn from "./TestSignIn.js";
import OrkInfo from "../Models/Infos/OrkInfo.js";
import HashToPoint from "../Cryptide/Hashing/H2P.js"

export default class SignUp {

    constructor(config, gVVK, enclaveRequest = null) {
        if (!Object.hasOwn(config, 'cmkOrkInfo')) { throw Error("CMK OrkInfo has not been included in config") }
        if (!Object.hasOwn(config, 'cvkOrkInfo')) { throw Error("CVK OrkInfo has not been included in config") }

        this.gVVK = gVVK

        /**
         * @type {OrkInfo[]}
         */
        this.cmkOrkInfo = config.cmkOrkInfo.map(info => OrkInfo.from(info));
        /**
         * @type {OrkInfo[]}
         */
        this.cvkOrkInfo = config.cvkOrkInfo.map(info => OrkInfo.from(info));

        // If enclaveRequest is provided, check if it contains fields
        if (enclaveRequest !== null) {

            if (!Object.hasOwn(enclaveRequest, 'refreshToken')) { throw Error("Enclave Request does not include refreshToken field") }
            if (!Object.hasOwn(enclaveRequest, 'getUserInfoFirst')) { throw Error("Enclave Request does not include getUserInfoFirst field") }
            if(enclaveRequest.customModel != undefined){
                if (!Object.hasOwn(enclaveRequest.customModel, 'Name')) { throw Error("Custom Model does not include Name field") }
                if (!Object.hasOwn(enclaveRequest.customModel, 'Data')) { throw Error("Custom Model does not include Data field") }
            }
        }
       
        this.enclaveRequest = enclaveRequest

        this.savedState = undefined;
    }
    
    /**
     * 
     * @param {string} username 
     * @param {string} password 
     */
    async start(username, password) { // should we implement a vendor object where the VVK signs the vendorUrl + homeOrk url?
        //hash username
        const uid = Bytes2Hex(await SHA256_Digest(username.toLowerCase()));

        const persona = 1; // this is new

        const r1 = RandomBigInt();
        const r2 = RandomBigInt();

        const gUser = await HashToPoint(await HMAC_forHashing([persona.toString(), this.gVVK]));
        const gBlurUser = gUser.times(r1);
        //convert password to point
        const gPass = await HashToPoint(password);
        const gBlurPass = gPass.times(r2);

        // Start Key Generation Flow
        const cmkGenFlow = new dKeyGenerationFlow(uid, this.cmkOrkInfo);
        const cmkGenShardData = await cmkGenFlow.GenShard(2, [gBlurUser, gBlurPass]);  // GenShard

        const {gPRISMAuth, VUID, gCMKAuth} = await this.getKeyPoints(cmkGenShardData.gMultiplied, [r1, r2], cmkGenShardData.gK1);

        const pre_cmkSendShard = cmkGenFlow.SetShard(gPRISMAuth, "CMK");  // async SendShard

        const cvkGenFlow = new dKeyGenerationFlow(VUID, this.cvkOrkInfo);
        const cvkGenShardData = await cvkGenFlow.GenShard(1, []);
        await cvkGenFlow.SetShard(gCMKAuth, "CVK");
        await pre_cmkSendShard;

        this.savedState = {
            uid: uid,
            gUser: gUser,
            gPass: gPass,
            cmkFlow: cmkGenFlow,
            cvkFlow: cvkGenFlow
        }

        return {
            ok: true,
            dataType: "userData",
            newAccount: true, // needed for when sign in ALSO creates CVKs
            publicKey: cvkGenShardData.gK1.toBase64(),
            uid: VUID
        };
    }

    async continue(model = null){
        if(this.savedState == null) throw Error("Saved state not defined");
        // Test sign in
        const testSignIn = new TestSignIn(this.cmkOrkInfo, this.cvkOrkInfo, false, false, false);
        await testSignIn.start(this.savedState.uid, this.savedState.gUser, this.savedState.gPass, this.gVVK)
        const resp = await testSignIn.continue(model);
        // Test dDecrypt
        //if(this.mode == "default"){
            // implement flag for which tests we want to run in new account
            //       const dDecryptFlow = new dDecryptionTestFlow(this.savedState.vendorUrl, Point.fromB64(this.savedState.gVVK), this.savedState.cvkPub, jwt, this.cvkOrkInfo[0][1]); // send first cvk ork's url as cvkOrkUrl, randomise in future?
        //         await dDecryptFlow.startTest();
       // }

        // Commit newly generated keys
        const pre_cmkCommit = this.savedState.cmkFlow.Commit("CMK");
        const pre_cvkCommit = this.savedState.cvkFlow.Commit("CVK");

        await pre_cmkCommit;
        await pre_cvkCommit;

        return resp;
    }

    /**
     * 
     * @param {Point[]} gMultiplied 
     * @param {bigint[]} r 
     * @param {Point} gCMK
     */
    async getKeyPoints(gMultiplied, r, gCMK){
        const gUserCMK = gMultiplied[0].times(mod_inv(r[0]));
        const gPassPRISM = gMultiplied[1].times(mod_inv(r[1]));

        const gPRISMAuth = Point.g.times(BigIntFromByteArray(await SHA256_Digest(gPassPRISM.toArray())));
        const hashed_gUserCMK = await SHA512_Digest(gUserCMK.toArray());

        const VUID = Bytes2Hex(hashed_gUserCMK.slice(-32)); 
        const CMKMul = mod(BigIntFromByteArray(hashed_gUserCMK.slice(0, 32)));
        const gCMKAuth = gCMK.times(CMKMul);

        return {VUID: VUID, gCMKAuth: gCMKAuth, gPRISMAuth: gPRISMAuth}
    }
}
