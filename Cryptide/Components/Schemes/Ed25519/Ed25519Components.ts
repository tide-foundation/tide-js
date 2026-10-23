// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

import { etc, Point } from "../../../Ed25519";
import { mod,} from "../../../Math";
import { BigIntFromByteArray, BigIntToByteArray} from "../../../Serialization";
import { Public, Private, Seed, BaseSeedComponent, BasePrivateComponent, BasePublicComponent } from "../../BaseComponent";
import Ed25519Scheme from "./Ed25519Scheme";
import { TideError } from "../../../../Errors/TideError";
import { TideJsErrorCodes } from "../../../../Errors/codes";

export class Ed25519PublicComponent extends BasePublicComponent{
    static Name = "Ed25519PublicComponent";
    static Version = "1";
    get Scheme() { return Ed25519Scheme; }
    get ComponentType() { return Public };

    /**@type {Uint8Array} */
    pb = undefined;
    /**@type {Point} */
    p = undefined;
    constructor(rawData){
        super();
        if(rawData instanceof Point){
            this.p = rawData;
        }else if(rawData instanceof Uint8Array){
            this.pb = rawData;
        }else{ throw new TideError({ code: TideJsErrorCodes.SERIAL_INVALID_TYPE, displayMessage: "Ed25519PublicComponent: unexpected type (expected Point or Uint8Array)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:42" }); }
    }
    get public() {
        if(!this.p && this.pb) this.p = Point.fromBytes(this.pb);
        else if(!this.p && !this.pb) throw new TideError({ code: TideJsErrorCodes.MODEL_INVALID_FIELD, displayMessage: "Ed25519PublicComponent.public: empty object (neither point nor bytes set)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:46" });
        return this.p;
    }

    get rawBytes() {
        if(!this.pb && this.p) this.pb = this.p.toRawBytes();
        else if(!this.pb && !this.p) throw new TideError({ code: TideJsErrorCodes.MODEL_INVALID_FIELD, displayMessage: "Ed25519PublicComponent.rawBytes: empty object (neither point nor bytes set)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:52" });
        return this.pb;
    }

    AddComponent(component){
        if(component instanceof Ed25519PublicComponent){
            return new Ed25519PublicComponent(this.public.add(component.public));
        }
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Ed25519PublicComponent.Add: mismatch with components (expected Ed25519PublicComponent)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:60" });
    }
    MultiplyComponent(component){
        if(component instanceof Ed25519PrivateComponent){
            return new Ed25519PublicComponent(this.public.mul(component.priv));
        }
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Ed25519PublicComponent.Multiply: mismatch with components (expected Ed25519PrivateComponent)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:66" });
    }
    MinusComponent(component){
        if(component instanceof Ed25519PublicComponent){
            return new Ed25519PublicComponent(this.public.add(component.public.negate()));
        }
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Ed25519PublicComponent.Minus: mismatch with components (expected Ed25519PublicComponent)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:72" });
    }
    EqualsComponent(component){
        if(component instanceof Ed25519PublicComponent){
            return this.public.equals(component.public);
        }
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Ed25519PublicComponent.Equals: mismatch with components (expected Ed25519PublicComponent)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:78" });
    }
    SerializeComponent(){
        return this.rawBytes.slice();
    }
}

export class Ed25519PrivateComponent extends BasePrivateComponent{
    static Name = "Ed25519PrivateComponent";
    static Version = "1";
    get Scheme() { return Ed25519Scheme; }
    get ComponentType() { return Private };

    /**@type {bigint} */
    p = undefined;
    /**@type {Uint8Array} */
    rB = undefined;

    get priv() {
        if(!this.p && this.rB) this.p = BigIntFromByteArray(this.rB);
        else if (!this.p && !this.rB) throw new TideError({ code: TideJsErrorCodes.MODEL_INVALID_FIELD, displayMessage: "Ed25519PrivateComponent.priv: empty object (neither bigint nor bytes set)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:98" });
        return this.p;
    }

    get rawBytes() {
        if(!this.rB && this.p) this.rB = BigIntToByteArray(this.p);
        else if(!this.rB && !this.p) throw new TideError({ code: TideJsErrorCodes.MODEL_INVALID_FIELD, displayMessage: "Ed25519PrivateComponent.rawBytes: empty object (neither bigint nor bytes set)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:104" });
        return this.rB;
    }

    constructor(rawData){
        super();
        if(typeof rawData == "bigint"){
            this.p = rawData;
        }else if(rawData instanceof Uint8Array){
            this.rB = rawData;
        }else{ throw new TideError({ code: TideJsErrorCodes.SERIAL_INVALID_TYPE, displayMessage: "Ed25519PrivateComponent: unexpected type (expected bigint or Uint8Array)", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:114" }); }
    }
    SerializeComponent(){
        return this.rawBytes.slice();
    }
    GetPublic(){
        return new Ed25519PublicComponent(Point.BASE.mul(this.priv));
    }
    static New(){
        return Ed25519SeedComponent.New().GetPrivate();
    }
}

export class Ed25519SeedComponent extends BaseSeedComponent{
    static Name = "Ed25519SeedComponent";
    static Version = "1";
    get Scheme() { return Ed25519Scheme; }
    get ComponentType() { return Seed };

    /**@type {Uint8Array} */
    rB = undefined;

    get rawBytes() {
        return this.rB;
    }

    constructor(rawData){
        super();
        if(rawData instanceof Uint8Array) this.rB = rawData.slice();
        else if(!rawData) this.rB = Ed25519SeedComponent.GenerateSeed(); // if nothing provided - self instanciate
        else throw new TideError({ code: TideJsErrorCodes.SERIAL_INVALID_TYPE, displayMessage: "Ed25519SeedComponent: expected Uint8Array or no argument", source: "tide-js/Cryptide/Components/Schemes/Ed25519/Ed25519Components.ts:144" });
    }

    SerializeComponent(){
        return this.rB.slice();
    }

    static GenerateSeed(){
        const head = etc.randomBytes(32);
        head[0] &= 248; // Clamp bits: 0b1111_1000,
        head[31] &= 127; // 0b0111_1111,
        head[31] |= 64; // 0b0100_0000
        return head;
    }

    GetPrivate(){
        return new Ed25519PrivateComponent(mod(BigIntFromByteArray(this.rawBytes)));
    }

    GetPublic(){
        return this.GetPrivate().GetPublic();
    }
    static New(){
        return new Ed25519SeedComponent(this.GenerateSeed());
    }
}