import { NodeClient, SimClient } from "../..";
import EnclaveToMobileTunnelClient from "../../Clients/EnclaveToMobileTunnelClient";
import WebSocketClientBase from "../../Clients/WebSocketClientBase";
import { DH } from "../../Cryptide";
import { Ed25519PrivateComponent, Ed25519PublicComponent } from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Components";
import Ed25519Scheme from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme";
import { Point } from "../../Cryptide/Ed25519";
import HashToPoint from "../../Cryptide/Hashing/H2P";
import { base64ToBase64Url, base64ToBytes, BigIntToByteArray, bytesToBase64, CreateTideMemoryFromArray, GetUID, GetValue, StringFromUint8Array, StringToUint8Array } from "../../Cryptide/Serialization";
import { ClientURLSignatureFormat, URLSignatureFormat } from "../../Cryptide/Signing/TideSignature";
import TideKey from "../../Cryptide/TideKey";
import { AuthenticateBasicReply, AuthenticateDeviceReply, CmkConvertReply, DeviceConvertReply, DevicePrismConvertReply, PrismConvertReply } from "../../Math/KeyAuthentication";
import BaseTideRequest from "../../Models/BaseTideRequest";
import KeyInfo from "../../Models/Infos/KeyInfo";
import PrismConvertResponse from "../../Models/Responses/KeyAuth/Convert/PrismConvertResponse";
import { Threshold, WaitForNumberofORKs } from "../../Tools/Utils";
import dVVKSigningFlow2Step from "../SigningFlows/dVVKSigningFlow2Step";
import VoucherFlow from "../VoucherFlows/VoucherFlow";

export default class dMobileAuthenticationFlow {

    constructor(scannedQrCodeAddress){ 
        this.webSocketClient = new WebSocketClientBase(scannedQrCodeAddress);
        this.requestInfo = this.webSocketClient.waitForMessage("request info");
        this.webSocketClient.sendMessage({
            type: "request info",
            message: ":)"
        }); // no need to await this since we're only curious about awaiting requestInfo
    }

    async configureFlowSettings(){
        let request = await this.requestInfo;
        const requiredProperties = ['appReq', 'appReqSignature', 'sessionKey', 'sessionKeySignature', 'voucherURL', 'devicePublicKey', 'vendorPublicKey'];

        for (const property of requiredProperties) {
            if (!request[property]) {
                throw new Error(`dMobileAuthenicationFlow: The configuration object is missing the required '${property}' property.`);
            }
        }

        this.homeOrkOrigin = new URL(this.webSocketClient.socketUrl).origin;
        this.appReq = request.appReq;
        this.sigAppReq = request.sigAppReq;
        this.sessKeyProof = request.sessKeyProof;
        this.browserPublicKey = TideKey.FromSerializedComponent(request.browserPublicKey);
        this.vendorPublicKey = TideKey.FromSerializedComponent(request.vendorPublicKey);
        this.voucherURL = request.voucherURL;
    }
    /**
     *  @param {string} username
     */
    async ensureReady(username) {
        await this.configureFlowSettings();

        // Verify details
        // otherwise, abort
        await this.browserPublicKey.verify(
            StringToUint8Array(this.appReq),
            base64ToBytes(this.sigAppReq));

        const appReqParsed = JSON.parse(this.appReq);
        this.enclaveSessionKeyPublic = TideKey.FromSerializedComponent(appReqParsed["gSessKeyPub"]);
        await this.enclaveSessionKeyPublic.verify(
            this.browserPublicKey.get_public_component().Serialize().ToBytes(),
            base64ToBytes(this.sessKeyProof));

        const returnURL = StringFromUint8Array(GetValue(base64ToBytes(appReqParsed["signedReturnURL"]), 0));
        const returnURLSignature = GetValue(base64ToBytes(appReqParsed["signedReturnURL"]), 1);
        await this.vendorPublicKey.verify(
            new URLSignatureFormat(returnURL).format(),
            returnURLSignature);

        this.sessionId = appReqParsed["sessionId"];

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
     * @param {boolean} rememberMe
     */
    async authenticate(devicePrivateKey, rememberMe, test=false) {
        if (!this.userId) throw 'Make sure you run ensureReady first';

        const deviceSessionKey = TideKey.NewKey(Ed25519Scheme);

        const simClient = new SimClient(this.homeOrkOrigin);
        const userInfo = await simClient.GetKeyInfo(this.userId);
        const userInfoRef = new KeyInfo(userInfo.UserId, userInfo.UserPublic, userInfo.UserM, userInfo.OrkInfo.slice()); // we need the full ork list later for the enclave encrypted data

        const signingFlow = new dVVKSigningFlow2Step(this.userId, userInfo.UserPublic, userInfo.OrkInfo, deviceSessionKey, null, this.voucherURL);

        const draft = CreateTideMemoryFromArray([this.enclaveSessionKeyPublic.get_public_component().Serialize().ToString(), new Uint8Array([rememberMe ? 1 : 0])]);
        const request = new BaseTideRequest((test ? "Test" : "") + "DeviceAuthentication", "1", "", draft);
        signingFlow.setRequest(request);
        const pre_encRequesti = signingFlow.preSign();

        // Compute appAuthi will awaiting request
        const dvk = TideKey.FromSerializedComponent(devicePrivateKey);
        const appAuthi = await DH.generateECDHi(userInfo.OrkInfo.map(o => o.orkPublic), dvk.get_private_component().priv); // To save time

        const encRequesti = await pre_encRequesti;

        const convertinfo = await DeviceConvertReply(
            encRequesti, 
            appAuthi.filter((_, i) => signingFlow.preSignState.bitwise[i] == true), // only use the appAuthis for the orks that responded (as shown in bitwise)
            signingFlow.orks.map(o => BigInt(o.orkID)), // use signing flow orks reference since these reference the orks that are part of this request
            userInfo.UserPublic,
            vouchers.qPub,
            vouchers.UDeObf,
            k,
            deviceSessionKey,
            "device_auth",
            this.sessionId,
            signingFlow.preSignState.GRj[0]
        );

        const toSend = convertinfo.decPrismRequesti.map(d => {
            return CreateTideMemoryFromArray([base64ToBytes(d.PRKRequesti), BigIntToByteArray(convertinfo.blurHCMKMul)])
        });
        const blindSig = (await signingFlow.sign(toSend)).sigs[0];


        const vendorData = await AuthenticateDeviceReply(
            convertinfo.VUID,
            blindSig,
            convertinfo.gCMKAuth,
            convertinfo.authToken,
            convertinfo.r4,
            convertinfo.gRMul,
            null
        );

        // Return enclave encrypted data
        this.enclaveEncryptedData = await this.browserPublicKey.asymmetricEncrypt(StringToUint8Array(JSON.stringify(
            {
                prkRequesti: convertinfo.decPrismRequesti.map(d => d.PRKRequesti),
                vendorData: vendorData,
                rememberMe: rememberMe,
                enclaveEntry: {
                    username: this.username,
                    //persona, not really supported yet
                    expired: convertinfo.expired,
                    userInfo: userInfoRef.toNativeTypeObject(),
                    orksBitwise: signingFlow.preSignState.bitwise,
                }
            }
        )));        
    }

    async finish(){
        if(!this.enclaveEncryptedData) throw 'Call Authenticate() first';

        const success = this.webSocketClient.waitForMessage("login success");
        await this.webSocketClient.sendMessage({
            type: "mobile completed",
            message: this.enclaveEncryptedData
        });
        await success;
    }

    async testAuthenticate(devicePrivateKey){
        await this.authenticate(devicePrivateKey, false, true);
        await this.finish();
    }

    async pairNewDevice(devicePrivateKey, password) {
        // This is where we submit the new device key to the orks 

        // Also we authenticate using the username, password

        // Later - when its a device allowing another device to pair - we'll need to show a qr code

        if (!this.userId) throw 'Make sure you run ensureReady first';

        const dvk = TideKey.FromSerializedComponent(devicePrivateKey);
        const sessionKey = TideKey.NewKey(Ed25519Scheme);

        const simClient = new SimClient(this.homeOrkOrigin);
        const userInfo = await simClient.GetKeyInfo(this.userId);

        const draft = CreateTideMemoryFromArray([
            dvk.get_public_component().Serialize().ToBytes(), 
            await dvk.sign(sessionKey.get_public_component().Serialize().ToBytes())],
        );

        const request = new BaseTideRequest("MigratePasswordToMobile", "1", "", draft);

        const signingFlow = new dVVKSigningFlow2Step(this.userId, userInfo.UserPublic, userInfo.OrkInfo, sessionKey, null, this.voucherURL);
        signingFlow.setRequest(request);

        const gPass = new Ed25519PublicComponent(await HashToPoint(password));
        const r1 = Ed25519PrivateComponent.New();
        const gBlurPass = gPass.MultiplyComponent(r1);

        const prismConvertResponses = (await signingFlow.preSign(gBlurPass.Serialize().ToString())).map(r => {
            return new PrismConvertResponse(StringFromUint8Array(GetValue(r, 0)), TideKey.FromSerializedComponent(GetValue(r, 1)).get_public_component().public); // conversion so we can use PrismConvertReply function
        });

        const convertInfo = await DevicePrismConvertReply(
            prismConvertResponses,
            signingFlow.orks.map(o => BigInt(o.orkID)), // use signing flow orks reference since these reference the orks that are part of this request
            signingFlow.orks.map(o => o.orkPublic), // use signing flow orks reference since these reference the orks that are part of this request
            r1.priv
        );

        const dynDatas = convertInfo.prkRequesti.map(p => {
            return CreateTideMemoryFromArray([base64ToBytes(p), BigIntToByteArray(convertInfo.timestampi)]);
        })

        const M_signature = (await signingFlow.sign(dynDatas)).sigs[0];

        // Now do test sign in
        await this.testAuthenticate(devicePrivateKey);


        // Now we commit
        // We'll need to construct the requests ourselves since this wasn't made as part of the key gen flow
        const preCommit = signingFlow.orks.map(o => new NodeClient(o.orkURL).Commit(this.userId, M_signature.slice(-32), sessionKey));
        await Promise.all(preCommit);
    }
}