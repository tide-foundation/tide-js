import { base64ToBytes, Bytes2Hex, bytesToBase64, ConcatUint8Arrays, getBytesFromInt16, Hex2Bytes } from "../Serialization.js";
import { Registery } from "./ComponentRegistry.js";
import BaseScheme from "./Schemes/BaseScheme.js";
import { SchemeType } from "./Schemes/SchemeRegistry.js";

export class BaseComponent{
    constructor(){}
    static Name = () => { throw Error("Name not implemented"); }
    static Version = () => { throw Error("Version not implemented"); }

    Add(component){
        if(component.Scheme == this.Scheme){
            let res = this.AddComponent(component);
            if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        }
        throw Error("Mismatch between components");
    }
    Multiply(component){
        if(component.Scheme == this.Scheme){
            let res = this.MultiplyComponent(component);
            if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        }
        throw Error("Mismatch between components");
    }
    Minus(component){
        if(component.Scheme == this.Scheme){
            let res = this.MinusComponent(component);
            if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        }
        throw Error("Mismatch between components");
    }
    Equals(component){
        if(component.Scheme == this.Scheme){
            let res = this.EqualsComponent(component);
            if(typeof res == "boolean") return res;
        }
        throw Error("Mismatch between components");
    }
    Mod(){
        let res = this.ModComponent();
        if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        throw Error("Mismatch between components");
    }
    ModInv(){
        let res = this.ModInvComponent();
        if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        throw Error("Mismatch between components");
    }

    AddComponent(component){ throw Error("Add not implemented"); }
    MultiplyComponent(component){ throw Error("Multiply not implemented"); }
    MinusComponent(component){ throw Error("Minus not implemented"); }
    EqualsComponent(component){ throw Error("Equals not implemented"); }
    ModComponent(){ throw Error("Mod not implemented"); }
    ModInvComponent(){ throw Error("Mod inv not implemented"); }
    SerializeComponent(){ throw Error("Serialize not implemented"); }
    /**@returns {BaseScheme} */
    get Scheme() { throw Error("Not implemented"); }
    /**@returns {string} */
    get ComponentType() { throw Error("Not implemented"); }

    /**
     * 
     * @returns {SerializedComponent}
     */
    Serialize(){
        let raw = this.SerializeComponent();
        let schemeInt = SchemeType.indexOf(this.Scheme);
        let componentTypeInt = ComponentKeyType.indexOf(this.ComponentType); 
        if(schemeInt == -1 || componentTypeInt == -1) throw Error("Could not find scheme or component type in registries");

        let schemeBytes = getBytesFromInt16(schemeInt);
        let header = ConcatUint8Arrays([new Uint8Array([componentTypeInt << 4]), schemeBytes]); // shift to the left (for when we have version, but all versions are 0 for now)

        return new SerializedComponent(ConcatUint8Arrays([header, raw]), this.ComponentType);
    }

    /**
    * @param {Uint8Array|string} serialized 
    * @returns {BaseComponent}
    */
    static DeserializeComponent(serialized){
        let b = [];
        if(!(serialized instanceof Uint8Array)){
            try{
                try{
                    b = Hex2Bytes(serialized);
                }catch{
                    b = base64ToBytes(serialized);
                }
            }catch{
                throw Error("Unable to deserialize component");
            }
        }else b = serialized;
        let scheme = SchemeType[toInt16(b.slice(1, 3), 0)];
        let k = (b[0] >> 4) & 0x0F;
        let keyType = ComponentKeyType[k];

        let component = Registery[scheme.Name][keyType];
        return component.Create(b.slice(3));
    }
}

export class BaseSeedComponent extends BaseComponent{
    get ComponentType() { return Seed; }
    static New() { throw Error("Not implemented"); }
    GetPublic() { throw Error("Not implemented"); }
    GetPrivate() { throw Error("Not implemented"); }
    get rawBytes() { throw Error("Not implemented"); }
}

export class BasePrivateComponent extends BaseComponent{
    get ComponentType() { return Private; }
    static New() { throw Error("Not implemented"); }
    GetPublic() { throw Error("Not implemented"); }
    get priv() { throw Error("Not implemented"); }
}

export class BasePublicComponent extends BaseComponent{
    get ComponentType() { return Public; }
    get public() { throw Error("Not implemented"); }
}

export class SerializedComponent{
    Bytes;
    ComponentType;

    constructor(bytes, compentType){
        this.Bytes = bytes;
        this.ComponentType = compentType;
    }

    ToBytes(){
        return this.Bytes;
    }
    ToString() {
        switch(this.ComponentType){
            case Seed:
                return bytesToBase64(this.Bytes);
            case Private:
                return bytesToBase64(this.Bytes);
            case Public:
                return Bytes2Hex(this.Bytes);
            case Symmetric:
                return bytesToBase64(this.Bytes);
            case QuantumPrivate:
                throw Error("Not implemented yet");
            case QuantumPublic:
                throw Error("Not implemented yet");
            default:
                throw Error("Unknown component type");
        }
    }
}



function toInt16(bytes, offset = 0) {
    const buffer = bytes.buffer;
    const view = new DataView(buffer);
    return view.getInt16(offset, true); // 'true' for little-endian, set to 'false' for big-endian
}

export const Seed = "Seed";
export const Private = "Private";
export const Public = "Public";
export const Symmetric = "Symmetric";
export const QuantumPrivate = "QuantumPrivate";
export const QuantumPublic = "QuantumPublic";
const ComponentKeyType = [
    Seed, // 0
    Private, // 1
    Public, // 2
    Symmetric, // 3
    QuantumPrivate, // 4
    QuantumPublic // 5
]

