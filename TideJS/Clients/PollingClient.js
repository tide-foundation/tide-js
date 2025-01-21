import ClientBase from "./ClientBase.js";
import { base64ToBytes, deserializeBitArray } from "../../Cryptide/Serialization.js";
import { Threshold } from "../Tools/Utils.js";

export default class PollingClient extends ClientBase {
    constructor(url) {
        super(url)
        this.stopPolling = false;
    }

    /**
    * @param {string[]} ids
    */
    async EstablishHttpTunnel(uid, ids) {
        const data = this._createFormData({
            'orkIds': ids.map(n => n.toString()),
        })

        // Establish the connection
        var channelId = "";
        const response = await this._post(`/Authentication/AccountRecovery/EstablishConnection?aruid=${uid}`, data);
        const responseData = await this._handleError(response, "EstablishConnection");
        if (responseData.split(":")[0] === "--CONNECTED--") {
            channelId = responseData.split(":")[1];
        }else{
            throw Error("orks.couldNotEstablishAConnection");
        }

        return channelId;


    }

    /**
    * @param {bigint} channelId 
    */
    async pollServer(channelId, uiUpdateCallback, signal) {
        const cId = channelId.toString();

        // Parameters for retry if server is down. 
        const maxRetries = 10; // Maximum number of retries
        let retryCount = 0;
        const retryInterval = 5000; // 5 seconds between retries
        const maxRetryDuration = 5 * 60 * 1000; // 5 minutes total retry duration..
        const startTime = Date.now();

        while (!this.stopPolling) {
            try {
                const response = await this._get(`/Authentication/AccountRecovery/WaitForUpdates?channelId=${cId}`, 60000, signal); // update timeout to something more appropriate
                if (!response.ok) throw new Error("ORK did not return status OK");

                const responseData = await response.json();

                if (responseData.status === "PING") {
                    continue;
                }

                if (responseData.status === "CANCELLED") {
                    return {status: "cancelled"}
                }
                if (responseData.status === "REJECTED") {
                    throw new Error(responseData.message)
                }
                if (responseData.status === "IN PROGRESS") {
                    uiUpdateCallback(responseData.key);
                    continue;
                }
                if (responseData.status === "RECOVERY") {
                    const encRequests = responseData.encRequest;
                    const bitwise = deserializeBitArray(base64ToBytes(responseData.bitwise));
                    if (encRequests.length < Threshold) break;
                    return { encRequests, bitwise, status: "recovered" };
                }
            } catch (error) {
                retryCount++;
                if (retryCount >= maxRetries || (Date.now() - startTime) >= maxRetryDuration) {
                    throw new Error("orks.pollingTimedOut");
                }
                await new Promise(resolve => setTimeout(resolve, retryInterval));
                continue;
            }
        }
        return {status: "cancelled"}
    }

    stop() {
        this.stopPolling = true;
    }
}
