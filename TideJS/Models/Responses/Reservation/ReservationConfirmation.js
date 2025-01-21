export default class ReservationConfirmation{
    constructor(user, purpose, expiry, clientKey, sessId, orkId, proximity, sig, raw){
        this.user = user;
        this.purpose = purpose;
        this.expiry = expiry;
        this.clientKey = clientKey;
        this.sessId = sessId;
        this.orkId = orkId;
        this.proximity = proximity;
        this.sig = sig;
        this.rawResConf = raw;
    }
    toString(){
        return this.rawResConf;
    }
    static from(data){
        const d = data.split("|")[0];
        const sig = data.split("|")[1];
        const json = JSON.parse(d);
        return new ReservationConfirmation(json.User, json.Purpose, json.Expiry, json.ClientKey, json.SessId, json.OrkId, json.Proximity, sig, data);
    }
}