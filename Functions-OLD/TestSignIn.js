import TideJWT from "../ModelsToSign/TideJWT.js";
import { BigIntToByteArray, bytesToBase64 } from "../Cryptide/Serialization.js";
import { RandomBigInt } from "../Cryptide/Math.js";
import dKeyAuthenticationFlow from "../Flow/dKeyAuthenticationFlow-OLD.js";
import { Point } from "../Cryptide/index.js";
import NetworkClient from "../Clients/NetworkClient.js";
import OrkInfo from "../Models/Infos/OrkInfo.js";

export default class TestSignIn{
    /**
     * 
     * @param {OrkInfo[]} cmkOrkInfo 
     * @param {OrkInfo[]} cvkOrkInfo 
     * @param {boolean} cmkCommitted 
     * @param {boolean} cvkCommitted 
     * @param {boolean} prismCommitted 
     */
    constructor(cmkOrkInfo, cvkOrkInfo, cmkCommitted, cvkCommitted, prismCommitted){
        this.cmkOrkInfo = cmkOrkInfo
        this.cvkOrkInfo = cvkOrkInfo // will change in future when vendor wants specific orks in new cvk rego
        this.cmkCommitted = cmkCommitted
        this.cvkCommitted = cvkCommitted
        this.prismCommitted = prismCommitted

        this.tokenRequested = true // Since we are going to verify if the test sign in worked this way!

        this.savedState = undefined;
    }

    /**
     * @param {string} uid
     * @param {Point} gUser 
     * @param {Point} gPass 
     * @param {string} gVVK 
     * @param {Point} cmkPub 
     * @param {Point} cvkPub 
     * @param {string} modelToSign
     * @returns 
     */
    async start(uid, gUser, gPass, gVVK){
        const startTime = BigInt(Math.floor(Date.now() / 1000));
        const r1 = RandomBigInt();
        const r2 = RandomBigInt();
        
        const cmkSimClient = new NetworkClient(this.cmkOrkInfo[0].orkURL);
        const pre_cmkInfo = cmkSimClient.GetKeyInfo(uid, this.cmkCommitted);

        const gBlurUser = gUser.times(r2);
        const gBlurPass = gPass.times(r1);

        const cmkInfo = await pre_cmkInfo;

        const authFlow = new dKeyAuthenticationFlow(this.cmkOrkInfo, this.cmkCommitted, this.cvkCommitted, this.prismCommitted, this.tokenRequested);
        const convertData = await authFlow.Convert(uid, gBlurUser, gBlurPass, r1, r2, startTime, cmkInfo.UserPublic);

        let cvkInfo = undefined;
        if(this.cvkOrkInfo == undefined){
            if(this.cvkCommitted == false) throw Error("Must provide cvkOrkInfo if cvkCommitted is false")
            cvkInfo = await cmkSimClient.GetKeyInfo(convertData.VUID, true);
        }else{
            const cvkSimClient = new NetworkClient(this.cvkOrkInfo[0].orkURL);
            cvkInfo = await cvkSimClient.GetKeyInfo(convertData.VUID, this.cvkCommitted);
        }

        authFlow.CVKorks = cvkInfo.OrkInfo;
        
        this.savedState = {
            uid: uid,
            vuid: convertData.VUID,
            convertData: convertData,
            gCVK: cvkInfo.UserPublic,
            authFlow: authFlow,
            gVVK: gVVK
        }

        return {
            ok: true,
            dataType: "userData",
            newAccount: !this.cvkCommitted, // if cvk is NOT committed, it IS a new account
            publicKey: cvkInfo.UserPublic.toBase64(),
            uid: convertData.VUID
        };
    }

    async continue(model=null){
        if(this.savedState == undefined) throw Error("No saved state");   

        await this.savedState.authFlow.Authenticate_and_PreSignInCVK(model == null ? null : model.Name);

        const resp = await this.savedState.authFlow.SignInCVK(model, this.savedState.gVVK);
        if(!(await TideJWT.verify(resp.jwt, this.savedState.gCVK))) throw Error("Test sign in failed");
        const sessionDataJSON = {
            Private: bytesToBase64(BigIntToByteArray(resp.sessKey)),
            JWT: resp.jwt
        };
        window.localStorage.setItem("TideSessionData", JSON.stringify(sessionDataJSON)); // store sessKey on successful login as a base64 encoding of the number

        return {
            ok: true,
            dataType: "completed",
            TideJWT: resp.jwt, 
            modelSig: resp.modelSig
        };
    }
}


