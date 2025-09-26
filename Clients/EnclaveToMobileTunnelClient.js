import TideKey from "../Cryptide/TideKey.js";
import WebSocketClientBase from "./WebSocketClientBase.js";

const guidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export default class EnclaveToMobileTunnelClient extends WebSocketClientBase{
    constructor(url){
        super(url + "/ws/mobileapp/start");
        this.url = url;
    }

    async initializeConnection(){
        const channelName = await this.waitForMessage("init");
        if(!guidRegex.test(channelName)) throw 'Channel name is not of GUID form. Aborting...'
        const orkConnectionAddress = this.url + "/ws/mobileApp/appConnect/" + channelName;
        return orkConnectionAddress;
    }

    async waitForAppReady(){
        await this.waitForMessage("ready"); // we need to make sure mobile is ready to recieve our request
    }

    /**
     * 
     * @param {string} voucherURL 
     * @param {TideKey} browserPublicKey 
     * @param {string} appReq
     * @param {string} appReqSignature
     * @param {string} sessionKeySignature
     * @param {TideKey} vendorPublicKey
     */
    async passEnclaveInfo(voucherURL, browserPublicKey, appReq, appReqSignature, sessionKeySignature, vendorPublicKey){
        await this.sendMessage({
            type: "requested info",
            message: {
                appReq: appReq,
                appReqSignature,
                sessionKeySignature,
                voucherURL,
                browserPublicKey: browserPublicKey.get_public_component().Serialize().ToString(),
                vendorPublicKey: vendorPublicKey.get_public_component().Serialize().ToString()
            }
        });
        const enclaveEncryptedData = await this.waitForMessage("mobile completed");
        return enclaveEncryptedData;
    }

    async indicateSuccess(){
        await this.sendMessage({
            type: "login success"
        });
    }
}