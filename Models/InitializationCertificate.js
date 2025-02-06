import { base64ToBytes, base64UrlToBase64, StringFromUint8Array } from "../Cryptide/Serialization.js";

export default class InitializationCertificate{
    /**
     * @param {string} data 
     */
    constructor(data){
        const d = data.split(".");
        if(d.length != 2) throw Error("Unexppect number of parts in InitCert");
        this.Header = new InitializationCertificateHeader(d[0]);
        this.Payload = new InitializationCertificatePayload(d[1]);
    }
    toPrettyObject(){
        return {
            "Header": this.Header.obj,
            "Payload": this.Payload.obj
        }
    }
}
class InitializationCertificateHeader{
    constructor(data){
        const s = StringFromUint8Array(base64ToBytes(base64UrlToBase64(data)));
        this.obj = JSON.parse(s);
    }
}
class InitializationCertificatePayload{
    constructor(data){
        const s = StringFromUint8Array(base64ToBytes(base64UrlToBase64(data)));
        this.obj = JSON.parse(s);
    }
}