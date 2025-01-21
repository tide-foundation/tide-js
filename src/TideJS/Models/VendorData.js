import { Ed25519PublicComponent } from "../../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import AuthRequest from "./AuthRequest.js";
export default class VendorData{
    /**
     * 
     * @param {string} VUID 
     * @param {Point} gCMKAuth 
     * @param {string} blindSig
     * @param {AuthRequest} AuthToken 
     */
    constructor(VUID, gCMKAuth, blindSig, AuthToken){
        this.VUID = VUID
        this.gCMKAuth = gCMKAuth
        this.blindSig = blindSig
        this.AuthToken = AuthToken
    }

    toString(){
        return JSON.stringify({
            'VUID': this.VUID,
            'gCMKAuth': new Ed25519PublicComponent(this.gCMKAuth).Serialize().ToString(),
            'blindSig': this.blindSig,
            'AuthToken': this.AuthToken.toString()
        })
    }

    static from(data){
        const json = JSON.parse(data);
        return new VendorData(json.VUID, json.gCMKAuth, json.blindSig, AuthRequest.from(json.AuthToken));
    }
}