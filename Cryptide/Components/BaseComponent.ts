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

import { base64ToBytes, Bytes2Hex, bytesToBase64, ConcatUint8Arrays, getBytesFromInt16, Hex2Bytes } from "../Serialization";
import { Registery } from "./ComponentRegistry";
import BaseScheme from "./Schemes/BaseScheme";
import { SchemeType } from "./Schemes/SchemeRegistry";
import { TideError } from "../../Errors/TideError";
import { TideJsErrorCodes } from "../../Errors/codes";

export class BaseComponent{
    constructor(){}
    static Name: any = () => { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Name not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.Name" }); }
    static Version: number = 0; // serialized in the low 4 bits of the first header byte (max 15)

    Add(component){
        if(component.Scheme == this.Scheme){
            let res = this.AddComponent(component) as any;
            if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        }
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Mismatch between components", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.Add" });
    }
    Multiply(component){
        if(component.Scheme == this.Scheme){
            let res = this.MultiplyComponent(component) as any;
            if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        }
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Mismatch between components", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.Multiply" });
    }
    Minus(component){
        if(component.Scheme == this.Scheme){
            let res = this.MinusComponent(component) as any;
            if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        }
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Mismatch between components", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.Minus" });
    }
    Equals(component){
        if(component.Scheme == this.Scheme){
            let res = this.EqualsComponent(component);
            if(typeof res == "boolean") return res;
        }
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Mismatch between components", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.Equals" });
    }
    Mod(){
        let res = this.ModComponent() as any;
        if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Mismatch between components", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.Mod" });
    }
    ModInv(){
        let res = this.ModInvComponent() as any;
        if(res instanceof BaseComponent && res.Scheme == this.Scheme) return res;
        throw new TideError({ code: TideJsErrorCodes.CRYPTO_COMPONENT_MISMATCH, displayMessage: "Mismatch between components", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.ModInv" });
    }

    AddComponent(component){ throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Add not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.AddComponent" }); }
    MultiplyComponent(component){ throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Multiply not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.MultiplyComponent" }); }
    MinusComponent(component){ throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Minus not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.MinusComponent" }); }
    EqualsComponent(component){ throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Equals not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.EqualsComponent" }); }
    ModComponent(){ throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Mod not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.ModComponent" }); }
    ModInvComponent(){ throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Mod inv not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.ModInvComponent" }); }
    SerializeComponent(): Uint8Array { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Serialize not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.SerializeComponent" }); }
    /**@returns {BaseScheme} */
    get Scheme(): any { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.Scheme" }); }
    /**@returns {string} */
    get ComponentType(): string { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.ComponentType" }); }

    Serialize(): SerializedComponent {
        let raw = this.SerializeComponent();
        let schemeInt = SchemeType.indexOf(this.Scheme as any);
        let componentTypeInt = ComponentKeyType.indexOf(this.ComponentType as any);
        if(schemeInt == -1 || componentTypeInt == -1) throw new TideError({ code: TideJsErrorCodes.CRYPTO_UNKNOWN_COMPONENT_TYPE, displayMessage: "Could not find scheme or component type in registries", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.Serialize" });

        let version = (this.constructor as any).Version;
        if(!Number.isInteger(version) || version < 0 || version > 0x0F) throw new TideError({ code: TideJsErrorCodes.MODEL_VALUE_OUT_OF_RANGE, displayMessage: `Component version ${version} does not fit in the 4-bit header field`, source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.Serialize" });

        let schemeBytes = getBytesFromInt16(schemeInt);
        let header = ConcatUint8Arrays([new Uint8Array([(componentTypeInt << 4) | (version & 0x0F)]), schemeBytes]); // high 4 bits: component type, low 4 bits: version (all tide-js components are version 0)

        return new SerializedComponent(ConcatUint8Arrays([header, raw]), this.ComponentType);
    }

    static DeserializeComponent(serialized: Uint8Array | string): BaseComponent {
        let b: any = [];
        if(!(serialized instanceof Uint8Array)){
            try{
                try{
                    b = Hex2Bytes(serialized);
                }catch{
                    b = base64ToBytes(serialized);
                }
            }catch{
                throw new TideError({ code: TideJsErrorCodes.CRYPTO_DESERIALIZE_FAILED, displayMessage: "Unable to deserialize component", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseComponent.DeserializeComponent" });
            }
        }else b = serialized;
        let scheme = SchemeType[toInt16(b.slice(1, 3), 0)];
        let k = (b[0] >> 4) & 0x0F;
        let keyType = ComponentKeyType[k];
        let version = b[0] & 0x0F;

        let component = Registery[scheme.Name][keyType];
        return component.Create(version, b.slice(3));
    }
}

export class BaseSeedComponent extends BaseComponent{
    get ComponentType() { return Seed; }
    static New() { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseSeedComponent.New" }); }
    GetPublic(): BasePublicComponent { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseSeedComponent.GetPublic" }); }
    GetPrivate(): BasePrivateComponent { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseSeedComponent.GetPrivate" }); }
    get rawBytes(): Uint8Array { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BaseSeedComponent.rawBytes" }); }
}

export class BasePrivateComponent extends BaseComponent{
    get ComponentType() { return Private; }
    static New() { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BasePrivateComponent.New" }); }
    GetPublic(): BasePublicComponent { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BasePrivateComponent.GetPublic" }); }
    get priv(): bigint { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BasePrivateComponent.priv" }); }
    get rawBytes(): Uint8Array { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BasePrivateComponent.rawBytes" }); }
}

export class BasePublicComponent extends BaseComponent{
    get ComponentType() { return Public; }
    get public(): any { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented", source: "tide-js/Cryptide/Components/BaseComponent.ts:BasePublicComponent.public" }); }
}

export class SerializedComponent{
    Bytes;
    ComponentType;

    constructor(bytes: Uint8Array, compentType: string){
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
                throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented yet", source: "tide-js/Cryptide/Components/BaseComponent.ts:SerializedComponent.ToString" });
            case QuantumPublic:
                throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Not implemented yet", source: "tide-js/Cryptide/Components/BaseComponent.ts:SerializedComponent.ToString" });
            default:
                throw new TideError({ code: TideJsErrorCodes.CRYPTO_UNKNOWN_COMPONENT_TYPE, displayMessage: "Unknown component type", source: "tide-js/Cryptide/Components/BaseComponent.ts:SerializedComponent.ToString" });
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

