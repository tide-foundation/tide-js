import TideKey from "../Cryptide/TideKey";
import WebSocketClientBase from "./WebSocketClientBase";

const guidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export default class EnclaveToMobileTunnelClient extends WebSocketClientBase{
    constructor(config){
        this.url = config.url;;
        super(this.url + "/ws/mobileapp/start", null);
    }

    async initializeConnection(){
        const channelName = await this.waitForMessage("init");
        if(!guidRegex.test(channelName)) throw 'Channel name is not of GUID form. Aborting...'
        const orkConnectionAddress = this.url + "/ws/mobileApp/appConnect/" + channelName;
        return orkConnectionAddress;
    }

    /**
     * 
     * @param {string} voucherURL 
     * @param {TideKey} devicePublicKey 
     */
    async passEnclaveInfo(voucherURL, devicePublicKey){
        await this.waitForMessage("request info"); // we need to make sure mobile is ready to recieve our request
        await this.sendMessage({
            type: "request info",
            message:{
                voucherURL: voucherURL,
                gBRK: devicePublicKey.get_public_component().Serialize().ToString()
            }
        });
        const enclaveEncryptedData = await this.waitForMessage("mobile completed");
        return enclaveEncryptedData;
    }
}