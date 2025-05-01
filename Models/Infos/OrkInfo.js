import { Point } from "../../Cryptide/Ed25519.js";
import { base64ToBytes, Hex2Bytes } from "../../Cryptide/Serialization.js";

export default class OrkInfo{
    /**
     * 
     * @param {string} orkID 
     * @param {Point} orkPublic 
     * @param {string} orkURL 
     * @param {Point} orkPaymentPublic
     */
    constructor(orkID, orkPublic, orkURL, orkPaymentPublic){
        this.orkID = orkID
        this.orkPublic = orkPublic
        this.orkURL = orkURL
        this.orkPaymentPublic = orkPaymentPublic
    }

    toString(){
        return JSON.stringify({
            Id: this.orkID,
            PublicKey: this.orkPublic.toBase64(),
            URL: this.orkURL,
            PaymentPublicKey: this.orkPaymentPublic.toBase64()
        });
    }

    toNativeTypeObject(){
        return {
            Id: this.orkID,
            PublicKey: this.orkPublic.toBase64(),
            URL: this.orkURL,
            PaymentPublicKey: this.orkPaymentPublic.toBase64()
        }
    }

    static fromNativeTypeObject(json){
        return new OrkInfo(json.Id, Point.fromBase64(json.PublicKey), json.URL, Point.fromBase64(json.PaymentPublicKey));
    }

    static from(json) {
        const { publickey, paymentpublickey, id, url } = normalizeKeys(json);
        const pub = Point.fromBytes(Hex2Bytes(publickey).slice(3));
        const paymentPub = Point.fromBytes(Hex2Bytes(paymentpublickey).slice(3));
        return new OrkInfo(id, pub, url, paymentPub);
    }
}
function normalizeKeys(obj) { // we are not case sensitive
    const normalized = {};
    Object.keys(obj).forEach(key => {
        normalized[key.toLowerCase()] = obj[key];
    });
    return normalized;
}
