import Point from "../../../Ed25519.js";
import { RandomBigInt } from "../../../Math.js";
import { BigIntFromByteArray, BigIntToByteArray, StringToUint8Array } from "../../../Serialization.js";
import { Public, Private, BaseComponent } from "../../BaseComponent.js";
import Ed25519Scheme from "./Ed25519Scheme.js";

export class Ed25519PublicComponent extends BaseComponent{
    static Name = "Ed25519PublicComponent";
    static Version = "1";
    Scheme = Ed25519Scheme;
    ComponentType = Public;

    pointBytes = [];
    /**@type {Point} */
    point = null;
    constructor(rawData){
        super();
        if(rawData instanceof Point){
            this.point = rawData;
        }else if(rawData instanceof Uint8Array){
            this.pointBytes = rawData;
        }else if(typeof rawData === "string"){
            this.pointBytes = StringToUint8Array(rawData);
        }
    }
    _point = () => {
        if(this.point == null) this.point = Point.from(this.pointBytes);
        return this.point;
    }
    _pointBytes = () => {
        if(this.pointBytes.length == 0) this.pointBytes = this.point.toArray();
        return this.pointBytes;
    }
    AddComponent(component){
        if(component instanceof Ed25519PublicComponent){
            return new Ed25519PublicComponent(this._point().add(component._point()));
        }
        throw Error("Mismatch with components");
    }
    MultiplyComponent(component){
        if(component instanceof Ed25519PrivateComponent){
            return new Ed25519PublicComponent(this._point().times(component.priv));
        }
        throw Error("Mismatch with components");
    }
    MinusComponent(component){
        if(component instanceof Ed25519PublicComponent){
            return new Ed25519PublicComponent(this._point().add(component._point().negate()));
        }
        throw Error("Mismatch with components");
    }
    EqualsComponent(component){
        if(component instanceof Ed25519PublicComponent){
            return this._point().isEqual(component._point());
        }
        throw Error("Mismatch with components");
    }
    SerializeComponent(){
        return this._pointBytes();
    }
}

export class Ed25519PrivateComponent extends BaseComponent{
    static Name = "Ed25519PrivateComponent";
    static Version = "1";
    Scheme = Ed25519Scheme;
    ComponentType = Private;

    /**@type {bigint} */
    priv = null;
    constructor(rawData){
        super();
        if(typeof rawData == "bigint"){
            this.priv = rawData;
        }else if(rawData instanceof Uint8Array){
            this.priv = BigIntFromByteArray(rawData);
        }else throw Error();
    }
    SerializeComponent(){
        return BigIntToByteArray(this.priv);
    }
    GetPublic(){
        return new Ed25519PublicComponent(Point.g.times(this.priv));
    }
    static New(){
        return new Ed25519PrivateComponent(RandomBigInt());
    }
}