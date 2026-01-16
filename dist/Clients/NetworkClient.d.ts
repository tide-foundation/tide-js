import KeyInfo from "../Models/Infos/KeyInfo";
import ClientBase from "./ClientBase";
export default class NetworkClient extends ClientBase {
    /**
     * @param {string} url
     */
    constructor(url?: any);
    GetPayerUrl(payerPublic: any): Promise<any>;
    /**
     *
     * @param {string} uid
     * @returns
     */
    GetKeyInfo(uid: any): Promise<KeyInfo>;
}
