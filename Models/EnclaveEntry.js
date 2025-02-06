import { base64ToBytes, bytesToBase64 } from "../Cryptide/Serialization.js";
import { Serialization } from "../Cryptide/index.js";
import KeyInfo from "./Infos/KeyInfo.js";
export default class EnclaveEntry{
    /**
     * @param {string} username
     * @param {string} persona
     * @param {bigint} expired
     * @param {KeyInfo} userInfo 
     * @param {(0|1)[]} orksBitwise 
     * @param {string[]} selfRequesti 
     * @param {Uint8Array} sessKey
     */
    constructor(username, persona, expired, userInfo, orksBitwise, selfRequesti, sessKey){
        this.username = username;
        this.persona = persona;
        this.expired = expired;
        this.userInfo = userInfo;
        this.orksBitwise = orksBitwise;
        this.selfRequesti = selfRequesti;
        this.sessKey = sessKey;
    }
    toString(){
        return JSON.stringify({
            username: this.username,
            persona: this.persona,
            expired: this.expired.toString(),
            userInfo: this.userInfo.toNativeTypeObject(),
            orksBitwise: JSON.stringify(this.orksBitwise),
            selfRequesti: this.selfRequesti,
            sessKey: bytesToBase64(this.sessKey)
        });
    }
    static from(data){
        const json = JSON.parse(data);
        const expired = BigInt(json.expired);
        const userInfo = KeyInfo.fromNativeTypeObject(json.userInfo); // includes uid + gCMK, ork URL + id + pubs 
        const orksBitwise = JSON.parse(json.orksBitwise);
        const selfRequesti = json.selfRequesti;
        const sessKey = base64ToBytes(json.sessKey);
        return new EnclaveEntry(json.username, json.persona, expired, userInfo, orksBitwise, selfRequesti, sessKey);
    }
}