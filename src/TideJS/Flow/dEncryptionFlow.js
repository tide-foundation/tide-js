import NodeClient from "../Clients/NodeClient.js";
import KeyInfo from "../Models/Infos/KeyInfo.js";
import Datum from "../Models/Datum.js";
import EncryptRequest from "../Math/EncryptRequest.js";
import PreSignInEncryptResponse from "../Models/Responses/KeyAuth/PreSignIn/PreSignInEncryptResponse.js";
import { CurrentTime, WaitForNumberOfORKs } from "../Tools/Utils.js";
import { SumPoints } from "../../Cryptide/Math.js";
import { GetLis } from "../Math/SecretShare.js";
import { generateECDHi } from "../../Cryptide/Encryption/DH.js";
export default class dEncryptionFlow{

    /**
     * @param {string} vuid 
     * @param {KeyInfo} keyInfo 
     */
    constructor(vuid, keyInfo){
        this.vuid = vuid
        this.keyPub = keyInfo.keyPublic
        this.CVKOrks = keyInfo.orkInfo
    }

    /**
     * 
     * @param {string} tideJWT 
     * @param {Datum[]} datums 
     * @param {string} sessKey
     */
    async PreSignInEncrypt(tideJWT, datums, sessKey){
        const clients = this.CVKOrks.map(ork => new NodeClient(ork.orkURL));

        const pre_PreSignInEncryptResp = clients.map((client, i) => client.PreSignInEncrypt(i, this.vuid, tideJWT, datums.length))

        // create encrypted fields here
        const timestamp = CurrentTime();
        const pre_partialRequests = datums.map(async (fd) => EncryptRequest.generatePartialRequest(this.keyPub, fd.data, timestamp));
        const partialRequests = await Promise.all(pre_partialRequests);

        // await threshold
        /**@type {PreSignInEncryptResponse[]} */
        const PreSignInEncryptResp = await WaitForNumberOfORKs(this.CVKOrks, pre_PreSignInEncryptResp, "CVK"); // here we await network requests from pre_gGCVKRi. this.CVKOrks is modified here
        const gCVKRi = datums.map((_, i) => SumPoints(PreSignInEncryptResp.map(r => r.gCVKRin[i]))); // sum points from index 0, index 1... from all responses
        const lis = GetLis(this.CVKOrks);
        const ECDHi = await generateECDHi(this.CVKOrks.map(ork => ork.orkPublic), sessKey); // i can either put this here, AFTER the WaitForTNumberOrks func or put it earlier, save the user 80ms, and have to manually sort and filter it here

        // will return encRequest
        const pre_encRequests = lis.map(async(li, i) => await EncryptRequest.generateEncryptedRequest(partialRequests, li, datums, gCVKRi, ECDHi[i])); // generate each encRequest for each cvkork
        const encRequests = await Promise.all(pre_encRequests);

        this.preSignInEncryptState = {
            gCVKRi,
            ECDHi,
            encRequests,
            Lis: lis,
            plainRequest:{
                EncFields: partialRequests.map(p => p.EncField),
                EncFieldChks: partialRequests.map(p => p.EncFieldChk),
                C1s: partialRequests.map(p => p.C1),
                Tags: datums.map(d => d.tag),
                GCVKRi: gCVKRi,
                Timestamp: timestamp
            }
        };
    }

    async SignEncryptedRequest(tideJWT){
        const clients = this.CVKOrks.map(ork => new NodeClient(ork.orkURL));

        const pre_encryptedSigs = clients.map((client, i) => client.SignEncRequest(this.vuid, tideJWT, this.preSignInEncryptState.encRequests[i]));
        const encryptedSigs = await Promise.all(pre_encryptedSigs);

        const serializedFields = await EncryptRequest.generateSerializedFields(
            encryptedSigs, 
            this.preSignInEncryptState.plainRequest, 
            this.preSignInEncryptState.Lis, 
            this.preSignInEncryptState.ECDHi,
            this.keyPub
        );
        return serializedFields;
    }
}