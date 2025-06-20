import { Utils } from "..";
import { BaseComponent } from "../Cryptide/Components/BaseComponent";
import { Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components";
import { base64ToBytes, base64UrlToBase64, DeserializeTIDE_KEY, StringFromUint8Array } from "../Cryptide/Serialization";
import TideKey from "../Cryptide/TideKey";

/**
 * 
 * @param {string} data 
 */
export function Doken(data){
    if (!(this instanceof Doken)) {
        throw new Error("The 'Doken' constructor must be invoked with 'new'.")
    }

    const parts = data.split(".");
    if(parts.length != 3) throw Error("Doken must be a 3 part token (including signature)");
    const dataRef = data.slice(0);

    const header = JSON.parse(StringFromUint8Array(base64ToBytes(base64UrlToBase64(parts[0]))));
    const payload = new DokenPayload(JSON.parse(StringFromUint8Array(base64ToBytes(base64UrlToBase64(parts[1])))));
    const signature = base64ToBytes(base64UrlToBase64(parts[1]));

    /**
     * 
     * @param {TideKey} sessionKeyToCheck 
     */
    this.validate = function (sessionKeyToCheck=null){
        // When an error is thrown - its a criticial error so the whole page should stop
        // But if validation just fails, then we return false with a reason why

        if(header.alg != "EdDSA") throw Error("Doken header alg expected to be EdDSA but got " + header.alg);
        if(header.typ != "doken") throw Error("Doken header typ expected to be doken but got " + header.typ);

        // Check expiry
        if(Utils.CurrentTime() > payload.exp) return {success: false, reason: "expired"}

        // Check session key matches
        if(sessionKeyToCheck){
            if(!sessionKeyToCheck.get_public_component().Equals(payload.sessionKey)) return {success: false, reason: "sessionkey mismatch"};
        }
    }

    class DokenPayload{
        constructor(json){
            var s = BaseComponent.DeserializeComponent(json["t.ssk"]);
            if(s instanceof Ed25519PublicComponent){
                this.sessionKey = s;
            }else throw Error("Unexpected session key type");

            var u = BaseComponent.DeserializeComponent(json["tideuserkey"]);
            if(u instanceof Ed25519PublicComponent){
                this.tideuserkey = u;
            }else throw Error("Unexpected tide user key type");

            if( typeof json.vuid === "string") this.vuid = json.vuid;
            else throw Error("Expected vuid to be string");

            // We don't need to deserialize user home ork here (enclave will never user it? it's for the client to know which ork to use)

            // Will be affected by 2032 problem
            if( typeof json.exp === "number") this.exp = json.exp;
            else throw Error("Expected exp to be a number");

            if( typeof json.aud === "string") this.aud = json.aud;
            else throw Error("Expected aud to be string");

            if( typeof json.realm_access === "object") this.realm_access = json.realm_access;
            else if(!json.realm_access) this.realm_access = null;
            else throw Error("Expected realm_access to be string");

            if( typeof json.resource_access === "object") this.resource_access = json.resource_access;
            else if(!json.resource_access) this.resource_access = null;
            else throw Error("Expected resource_access to be string");
        }
    }
}
