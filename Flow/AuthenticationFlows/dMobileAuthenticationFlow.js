import { NodeClient, SimClient } from "../../index.js";
import WebSocketClientBase from "../../Clients/WebSocketClientBase.js";
import { DH } from "../../Cryptide/index.js";
import { Ed25519PrivateComponent, Ed25519PublicComponent } from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import Ed25519Scheme from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme.js";
import HashToPoint from "../../Cryptide/Hashing/H2P.js";
import { base64ToBase64Url, base64ToBytes, BigIntFromByteArray, BigIntToByteArray, bytesToBase64, CreateTideMemoryFromArray, GetUID, GetValue, StringFromUint8Array, StringToUint8Array } from "../../Cryptide/Serialization.js";
import TideKey from "../../Cryptide/TideKey.js";
import { AuthenticateBasicReply, AuthenticateDeviceReply, CmkConvertReply, DeviceConvertReply, DevicePrismConvertReply, PrismConvertReply } from "../../Math/KeyAuthentication.js";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import KeyInfo from "../../Models/Infos/KeyInfo.js";
import PrismConvertResponse from "../../Models/Responses/KeyAuth/Convert/PrismConvertResponse.js";
import dVVKSigningFlow2Step from "../SigningFlows/dVVKSigningFlow2Step.js";
import { sortORKs } from "../../Tools/Utils.js";

export default class dMobileAuthenticationFlow {

    constructor(scannedQrCodeAddress){ 
        this.webSocketClient = new WebSocketClientBase(scannedQrCodeAddress);
        this.requestInfo = this.webSocketClient.waitForMessage("requested info");
        this.webSocketClient.sendMessage({
            type: "ready",
            message: ":)"
        }); // no need to await this since we're only curious about awaiting requestInfo
    }

    async configureFlowSettings(){
        let request = await this.requestInfo;
        const requiredProperties = ['appReq', 'appReqSignature', 'sessionKey', 'sessionKeySignature', 'voucherURL', 'browserPublicKey', 'vendorPublicKey'];

        for (const property of requiredProperties) {
            if (!request[property]) {
                throw new Error(`dMobileAuthenicationFlow: The configuration object is missing the required '${property}' property.`);
            }
        }

        const socketUrl = this.webSocketClient.getSocketUrl(); // or `.socketUrl` if you added a getter
        const u = new URL(socketUrl);

        if (u.protocol === 'wss:') u.protocol = 'https:';
        else if (u.protocol === 'ws:') u.protocol = 'http:';
        else throw new Error('Expected ws:// or wss:// URL');

        this.homeOrkOrigin = u.origin;

        this.appReq = request.appReq;
        this.sigAppReq = request.appReqSignature;
        this.sessKeyProof = request.sessionKeySignature;
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

        this.sessionId = appReqParsed["sessionId"];

        // Checks if gBRK is familiar (expected to do that (outside this flow) in mobile app)
        // ...

        // Short printable source URL

        this.userId = await GetUID(username);
        this.username = username;
        return {
            browserKeyIdentifier: this.browserPublicKey.get_public_component().Serialize().ToString(),
            vendorReturnURL: appReqParsed['returnURL'],
            userID: this.userId
        }
    }

    /**
     * 
     * @param {string} devicePrivateKey 
     * @param {boolean} rememberMe
     */
    async authenticate(devicePrivateKey, rememberMe, testSessionKey=null) {
        if (!this.userId) throw 'Make sure you run ensureReady first';

        const deviceSessionKey = testSessionKey ? testSessionKey : TideKey.NewKey(Ed25519Scheme);

        const simClient = new SimClient(this.homeOrkOrigin);
        const userInfo = await simClient.GetKeyInfo(this.userId);
        const userInfoRef = new KeyInfo(userInfo.UserId, userInfo.UserPublic, userInfo.UserM, userInfo.OrkInfo.slice()); // we need the full ork list later for the enclave encrypted data

        const signingFlow = new dVVKSigningFlow2Step(this.userId, userInfo.UserPublic, userInfo.OrkInfo, deviceSessionKey, null, this.voucherURL);

        const draft = CreateTideMemoryFromArray([this.enclaveSessionKeyPublic.get_public_component().Serialize().ToBytes(), new Uint8Array([rememberMe ? 1 : 0])]);
        const request = new BaseTideRequest((testSessionKey ? "Test" : "") + "DeviceAuthentication", "1", "", draft);
        signingFlow.setRequest(request);
        const pre_encRequesti = signingFlow.preSign();

        // Compute appAuthi will awaiting request
        const dvk = TideKey.FromSerializedComponent(devicePrivateKey);
        const encRequesti = await pre_encRequesti;
        const appAuthi = await DH.generateECDHi(sortORKs(userInfo.OrkInfo).map(o => o.orkPublic), dvk.get_private_component().priv); // must be sorted! 

        const convertinfo = await DeviceConvertReply(
            encRequesti, 
            appAuthi.filter((_, i) => signingFlow.preSignState.bitwise[i] == true), // only use the appAuthis for the orks that responded (as shown in bitwise)
            signingFlow.orks.map(o => BigInt(o.orkID)), // use signing flow orks reference since these reference the orks that are part of this request
            userInfo.UserPublic,
            signingFlow.getVouchers().qPub,
            signingFlow.getVouchers().UDeObf,
            signingFlow.getVouchers().k,
            this.enclaveSessionKeyPublic.get_public_component(),
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
            null // - GVRK hereeee
        );

        // Return enclave encrypted data
        this.enclaveEncryptedData = bytesToBase64(await this.browserPublicKey.asymmetricEncrypt(StringToUint8Array(JSON.stringify(
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
        ))));        
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

    async testAuthenticate(devicePrivateKey, sessionKey, rememberMe){
        await this.authenticate(devicePrivateKey, rememberMe, sessionKey);
        await this.finish();
    }

    async pairNewDevice(devicePrivateKey, password, rememberMe=false, sessKey=null) {
        // This is where we submit the new device key to the orks 

        // Also we authenticate using the username, password

        // Later - when its a device allowing another device to pair - we'll need to show a qr code

        if (!this.userId) throw 'Make sure you run ensureReady first';

        const dvk = TideKey.FromSerializedComponent(devicePrivateKey);
        const sessionKey = sessKey != null ? sessKey : TideKey.NewKey(Ed25519Scheme);

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

        const prismConvertResponses = (await signingFlow.preSign(gBlurPass.Serialize().ToBytes())).map(r => {
            return new PrismConvertResponse(bytesToBase64(GetValue(r, 0)), TideKey.FromSerializedComponent(GetValue(r, 1)).get_public_component().public); // conversion so we can use PrismConvertReply function
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
        await this.testAuthenticate(devicePrivateKey, sessionKey, rememberMe);


        // Now we commit
        // We'll need to construct the requests ourselves since this wasn't made as part of the key gen flow
        const preCommit = signingFlow.orks.map(o => new NodeClient(o.orkURL).Commit(this.userId, BigIntFromByteArray(M_signature.slice(-32)), sessionKey.get_public_component().public));
        await Promise.all(preCommit);
    }
}