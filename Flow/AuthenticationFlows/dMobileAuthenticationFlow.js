import { NodeClient, SimClient } from "../..";
import { DH } from "../../Cryptide";
import { Ed25519PublicComponent } from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Components";
import { Point } from "../../Cryptide/Ed25519";
import { base64ToBase64Url, base64ToBytes, bytesToBase64, GetUID, GetValue, StringFromUint8Array, StringToUint8Array } from "../../Cryptide/Serialization";
import { ClientURLSignatureFormat, URLSignatureFormat } from "../../Cryptide/Signing/TideSignature";
import TideKey from "../../Cryptide/TideKey";
import { AuthenticateBasicReply, CmkConvertReply, DeviceConvertReply } from "../../Math/KeyAuthentication";
import KeyInfo from "../../Models/Infos/KeyInfo";
import { Threshold, WaitForNumberofORKs } from "../../Tools/Utils";
import VoucherFlow from "../VoucherFlows/VoucherFlow";

export default class dMobileAuthenticationFlow{

    /**
     * @param {string} homeOrkUrl
     * @param {string} appReq 
     * @param {*} sigAppReq 
     * @param {*} sessKeyProof 
     * @param {string} browserPublicKey 
     * @param {Point} gVVK
     */
    constructor(homeOrkUrl, appReq, sigAppReq, sessKeyProof, browserPublicKey, gVVK){
        this.homeOrkUrl = homeOrkUrl;
        this.appReq = appReq;
        this.sigAppReq = sigAppReq;
        this.sessKeyProof = sessKeyProof;
        this.browserPublicKey = TideKey.FromSerializedComponent(browserPublicKey);
        this.vendorPublicKey = new TideKey(new Ed25519PublicComponent(gVVK));
    }
    
// Maybe let's not do an extends


// Too many things in Convert that are different



    /**
     *  @param {string} username
     */
    async ensureReady(username){
        // Verify details
        // otherwise, abort
        await this.browserPublicKey.verify(
            StringToUint8Array(this.appReq), 
            base64ToBytes(this.sigAppReq));

        const appReqParsed = JSON.parse(this.appReq);
        this.sessionKeyPublic = TideKey.FromSerializedComponent(appReqParsed["gSessKeyPub"]);
        await this.sessionKeyPublic.verify(
            this.browserPublicKey.get_public_component().Serialize().ToBytes(), 
            base64ToBytes(this.sessKeyProof));

        const returnURL = StringFromUint8Array(GetValue(base64ToBytes(appReqParsed["signedReturnURL"]), 0));
        const returnURLSignature = GetValue(base64ToBytes(appReqParsed["signedReturnURL"]), 1);
        await this.vendorPublicKey.verify(
            new URLSignatureFormat(returnURL).format(), 
            returnURLSignature);

        // Checks if gBRK is familiar (expected to do that (outside this flow) in mobile app)
        // ...

        // Short printable source URL

        this.userId = await GetUID(username);
        this.username = username;
        return {
            browserKeyIdentifier: this.browserPublicKey.get_public_component().Serialize().ToString(),
            vendorReturnURL: returnURL,
            userID: this.userId
        }
    }

    /**
     * 
     * @param {string} devicePrivateKey 
     * @param {string} purpose
     * @param {string} sessionId
     * @param {boolean} rememberMe
     */
    async authenticate(devicePrivateKey, purpose, sessionId, rememberMe){
        if(!this.userId) throw 'Make sure you run ensureReady first';

        const simClient = new SimClient(this.homeOrkUrl);
        const userInfo = await simClient.GetKeyInfo(this.userId);

        const userInfoRef = new KeyInfo(userInfo.UserId, userInfo.UserPublic, userInfo.UserM, userInfo.OrkInfo.slice()); // we need the full ork list later for the enclave encrypted data

        const convertClients = userInfo.OrkInfo.map(ork => new NodeClient(ork.orkURL));
        const voucherFlow = new VoucherFlow(userInfo.OrkInfo.map(o => o.orkPaymentPublic), JSON.parse(this.appReq)["voucherURL"], "signin");
        const {vouchers, k} = await voucherFlow.GetVouchers();

        const pre_ConvertResponses = convertClients.map((client, i) => client.DeviceConvert(i, this.userId, appReqParsed["gSessKeyPub"], rememberMe, vouchers.toORK(i), userInfo.UserM, true, true));

        const dvk = TideKey.FromSerializedComponent(devicePrivateKey);
        const appAuthi = await DH.generateECDHi(userInfo.OrkInfo.map(o => o.orkPublic), dvk.get_private_component().priv); // To save time

        const {fulfilledResponses, bitwise} = await WaitForNumberofORKs(userInfo.OrkInfo, pre_ConvertResponses, "CMK", Threshold, null, appAuthi);
        const ids = userInfo.OrkInfo.map(c => BigInt(c.orkID));

        const convertInfo = await DeviceConvertReply(
            fulfilledResponses.map(c => c.DeviceConvertResponse),
            appAuthi,
            ids, 
            userInfo.UserPublic,
            vouchers.qPub,
            vouchers.UDeObf,
            k,
            this.sessionKeyPublic,
            purpose,
            sessionId
        );

        // Start authenticate
        const authenticateClients = userInfo.OrkInfo.map(ork => new NodeClient(ork.orkURL)); // recreate the clients with the updated userInfo.OrkInfo orks that responded from the Convert (remember userInfo.OrkInfo is changed in WaitForNumberofORKs)

        const pre_encSig = authenticateClients.map((client, i) => client.DeviceAuthenticate(
            this.keyInfo.UserId, 
            convertInfo.decPrismRequesti.map(d => d.PRKRequesti), 
            convertInfo.blurHCMKMul,
            serializeBitArray(bitwise)));
        const encSig = await Promise.all(pre_encSig);

        const vendorData = await AuthenticateBasicReply(
            convertInfo.VUID,
            appAuthi,
            encSig,
            convertInfo.gCMKAuth,
            convertInfo.authToken,
            convertInfo.r4,
            convertInfo.gRMul,
            null
        );

        // Return enclave encrypted data
        const enclaveEncryptedData = await this.browserPublicKey.asymmetricEncrypt(StringToUint8Array(JSON.stringify(
            {
                prkRequesti: convertInfo.decPrismRequesti.map(d => d.PRKRequesti),
                vendorData: vendorData,
                rememberMe: rememberMe,
                enclaveEntry: {
                    username: this.username,
                    //persona, not really supported yet
                    expired: convertInfo.expired,
                    userInfo: userInfoRef.toNativeTypeObject(),
                    orksBitwise: bitwise,
                }
            }
        )));
        
        return enclaveEncryptedData;
    }

    pairNewDevice(username, password){
        // This is where we submit the new device key to the orks 

        // Also we authenticate using the username, password

        // Later - when its a device allowing another device to pair - we'll need to show a qr code

    }
}