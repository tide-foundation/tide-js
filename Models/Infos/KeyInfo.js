import { Point } from "../Cryptide/index.js";
import OrkInfo from "./OrkInfo.js";

export default class KeyInfo{
    /**
     * 
     * @param {string} userId 
     * @param {Point} userPublic 
     * @param {string} userM
     * @param {OrkInfo[]} orkInfo 
     */
    constructor(userId, userPublic, userM, orkInfo){
        this.UserId = userId
        this.UserPublic = userPublic
        this.UserM = userM;
        this.OrkInfo = orkInfo
    }

    toString(){
        return JSON.stringify({
            UserId: this.UserId,
            UserPublic: this.UserPublic.toBase64(),
            UserM: this.UserM,
            OrkInfos: this.OrkInfo.map(info => info.toString())
        })
    }

    toNativeTypeObject(){
        return {
            UserId: this.UserId,
            UserPublic: this.UserPublic.toBase64(),
            UserM: this.UserM,
            OrkInfos: this.OrkInfo.map(info => info.toNativeTypeObject())
        }
    }

    static from(data){
        const json = JSON.parse(data);
        const pub = Point.fromB64(json.UserPublic);
        const orkInfo = json.OrkInfos.map(orkInfo => OrkInfo.from(orkInfo));
        return new KeyInfo(json.UserId, pub, json.UserM, orkInfo);
    }

    static fromNativeTypeObject(json){
        return new KeyInfo(json.UserId, Point.fromB64(json.UserPublic), json.UserM, json.OrkInfos.map(o => OrkInfo.fromNativeTypeObject(o)));
    }
}