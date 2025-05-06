import { etc, Point } from "../../../Ed25519.js";
import { SHA512_Digest } from "../../../Hashing/Hash.js";
import { mod, RandomBigInt } from "../../../Math.js";
import { BigIntFromByteArray, BigIntToByteArray, StringToUint8Array } from "../../../Serialization.js";
import { Public, Private, BaseComponent, Seed, BaseSeedComponent, BasePrivateComponent, BasePublicComponent } from "../../BaseComponent.js";
import Ed25519Scheme from "./Ed25519Scheme.js";

export class Ed25519PublicComponent extends BasePublicComponent{
    static Name = "Ed25519PublicComponent";
    static Version = "1";
    get Scheme() { return Ed25519Scheme; }

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
        }else{ throw Error("unexpected type;") }
    }
    get public() {
        if(!this.p && this.pb) this.p = Point.fromBytes(this.pb);
        else if(!this.p && !this.pb) throw Error("empty object");
        return this.p;
    }
    
    get rawBytes() {
        if(!this.pb && this.p) this.pb = this.p.toRawBytes();
        else if(!this.pb && !this.p) throw Error("empty object");
        return this.pb;
    }

    AddComponent(component){
        if(component instanceof Ed25519PublicComponent){
            return new Ed25519PublicComponent(this.public.add(component.public));
        }
        throw Error("Mismatch with components");
    }
    MultiplyComponent(component){
        if(component instanceof Ed25519PrivateComponent){
            return new Ed25519PublicComponent(this.public.mul(component.priv));
        }
        throw Error("Mismatch with components");
    }
    MinusComponent(component){
        if(component instanceof Ed25519PublicComponent){
            return new Ed25519PublicComponent(this.public.add(component.public.negate()));
        }
        throw Error("Mismatch with components");
    }
    EqualsComponent(component){
        if(component instanceof Ed25519PublicComponent){
            return this.public.equals(component.public);
        }
        throw Error("Mismatch with components");
    }
    SerializeComponent(){
        return this.rawBytes.slice();
    }
}

export class Ed25519PrivateComponent extends BasePrivateComponent{
    static Name = "Ed25519PrivateComponent";
    static Version = "1";
    Scheme = Ed25519Scheme;
    ComponentType = Private;

    /**@type {bigint} */
    p = undefined;
    /**@type {Uint8Array} */
    rB = undefined;

    get priv() {
        if(!this.p && this.rB) this.p = BigIntFromByteArray(this.rB);
        else if (!this.p && !this.rB) throw Error("Empty object");
        return this.p;
    }

    get rawBytes() {
        if(!this.rB && this.p) this.rB = BigIntToByteArray(this.p);
        else if(!this.rB && !this.p) throw Error("Empty object");
        return this.rB;
    }

    constructor(rawData){
        super();
        if(typeof rawData == "bigint"){
            this.p = rawData;
        }else if(rawData instanceof Uint8Array){
            this.rB = rawData;
        }else{ throw Error("unexpected type;") }
    }
    SerializeComponent(){
        return this.rB.slice();
    }
    GetPublic(){
        return new Ed25519PublicComponent(Point.BASE.mul(this.p));
    }
    static New(){
        return Ed25519SeedComponent.New().GetPrivate();
    }
}

export class Ed25519SeedComponent extends BaseSeedComponent{
    static Name = "Ed25519SeedComponent";
    static Version = "1";
    Scheme = Ed25519Scheme;
    ComponentType = Seed;

    /**@type {Uint8Array} */
    rB = undefined;

    get rawBytes() {
        return this.rB;
    }

    constructor(rawData){
        super();
        if(rawData instanceof Uint8Array) this.rB = rawData.slice();
        else if(!rawData) this.rB = Ed25519SeedComponent.GenerateSeed(); // if nothing provided - self instanciate
        else throw Error("Expecting Uint8Array or nothing for constructor");
    }

    SerializeComponent(){
        return this.rB.slice();
    }

    static GenerateSeed(){
        const head = etc.randomBytes(32);
        head[0] &= 248; // Clamp bits: 0b1111_1000,
        head[31] &= 127; // 0b0111_1111,
        head[31] |= 64; // 0b0100_0000
        return mod(BigIntFromByteArray(head));
    }

    GetPrivate(){
        return new Ed25519PrivateComponent(this.rB);
    }

    GetPublic(){
        return this.GetPrivate().GetPublic();
    }
    static async New(){
        return new Ed25519SeedComponent(this.GenerateSeed());
    }
}