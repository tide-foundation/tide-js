"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.QuantumPublic = exports.QuantumPrivate = exports.Symmetric = exports.Public = exports.Private = exports.Seed = exports.SerializedComponent = exports.BasePublicComponent = exports.BasePrivateComponent = exports.BaseSeedComponent = exports.BaseComponent = void 0;
const Serialization_1 = require("../Serialization");
const ComponentRegistry_1 = require("./ComponentRegistry");
const SchemeRegistry_1 = require("./Schemes/SchemeRegistry");
class BaseComponent {
    constructor() { }
    Add(component) {
        if (component.Scheme == this.Scheme) {
            let res = this.AddComponent(component);
            if (res instanceof BaseComponent && res.Scheme == this.Scheme)
                return res;
        }
        throw Error("Mismatch between components");
    }
    Multiply(component) {
        if (component.Scheme == this.Scheme) {
            let res = this.MultiplyComponent(component);
            if (res instanceof BaseComponent && res.Scheme == this.Scheme)
                return res;
        }
        throw Error("Mismatch between components");
    }
    Minus(component) {
        if (component.Scheme == this.Scheme) {
            let res = this.MinusComponent(component);
            if (res instanceof BaseComponent && res.Scheme == this.Scheme)
                return res;
        }
        throw Error("Mismatch between components");
    }
    Equals(component) {
        if (component.Scheme == this.Scheme) {
            let res = this.EqualsComponent(component);
            if (typeof res == "boolean")
                return res;
        }
        throw Error("Mismatch between components");
    }
    Mod() {
        let res = this.ModComponent();
        if (res instanceof BaseComponent && res.Scheme == this.Scheme)
            return res;
        throw Error("Mismatch between components");
    }
    ModInv() {
        let res = this.ModInvComponent();
        if (res instanceof BaseComponent && res.Scheme == this.Scheme)
            return res;
        throw Error("Mismatch between components");
    }
    AddComponent(component) { throw Error("Add not implemented"); }
    MultiplyComponent(component) { throw Error("Multiply not implemented"); }
    MinusComponent(component) { throw Error("Minus not implemented"); }
    EqualsComponent(component) { throw Error("Equals not implemented"); }
    ModComponent() { throw Error("Mod not implemented"); }
    ModInvComponent() { throw Error("Mod inv not implemented"); }
    SerializeComponent() { throw Error("Serialize not implemented"); }
    /**@returns {BaseScheme} */
    get Scheme() { throw Error("Not implemented"); }
    /**@returns {string} */
    get ComponentType() { throw Error("Not implemented"); }
    /**
     *
     * @returns {SerializedComponent}
     */
    Serialize() {
        let raw = this.SerializeComponent();
        let schemeInt = SchemeRegistry_1.SchemeType.indexOf(this.Scheme);
        let componentTypeInt = ComponentKeyType.indexOf(this.ComponentType);
        if (schemeInt == -1 || componentTypeInt == -1)
            throw Error("Could not find scheme or component type in registries");
        let schemeBytes = (0, Serialization_1.getBytesFromInt16)(schemeInt);
        let header = (0, Serialization_1.ConcatUint8Arrays)([new Uint8Array([componentTypeInt << 4]), schemeBytes]); // shift to the left (for when we have version, but all versions are 0 for now)
        return new SerializedComponent((0, Serialization_1.ConcatUint8Arrays)([header, raw]), this.ComponentType);
    }
    /**
    * @param {Uint8Array|string} serialized
    * @returns {BaseComponent}
    */
    static DeserializeComponent(serialized) {
        let b = [];
        if (!(serialized instanceof Uint8Array)) {
            try {
                try {
                    b = (0, Serialization_1.Hex2Bytes)(serialized);
                }
                catch {
                    b = (0, Serialization_1.base64ToBytes)(serialized);
                }
            }
            catch {
                throw Error("Unable to deserialize component");
            }
        }
        else
            b = serialized;
        let scheme = SchemeRegistry_1.SchemeType[toInt16(b.slice(1, 3), 0)];
        let k = (b[0] >> 4) & 0x0F;
        let keyType = ComponentKeyType[k];
        let component = ComponentRegistry_1.Registery[scheme.Name][keyType];
        return component.Create(b.slice(3));
    }
}
exports.BaseComponent = BaseComponent;
BaseComponent.Name = () => { throw Error("Name not implemented"); };
BaseComponent.Version = () => { throw Error("Version not implemented"); };
class BaseSeedComponent extends BaseComponent {
    get ComponentType() { return exports.Seed; }
    static New() { throw Error("Not implemented"); }
    GetPublic() { throw Error("Not implemented"); }
    GetPrivate() { throw Error("Not implemented"); }
    get rawBytes() { throw Error("Not implemented"); }
}
exports.BaseSeedComponent = BaseSeedComponent;
class BasePrivateComponent extends BaseComponent {
    get ComponentType() { return exports.Private; }
    static New() { throw Error("Not implemented"); }
    GetPublic() { throw Error("Not implemented"); }
    get priv() { throw Error("Not implemented"); }
}
exports.BasePrivateComponent = BasePrivateComponent;
class BasePublicComponent extends BaseComponent {
    get ComponentType() { return exports.Public; }
    get public() { throw Error("Not implemented"); }
}
exports.BasePublicComponent = BasePublicComponent;
class SerializedComponent {
    constructor(bytes, compentType) {
        this.Bytes = bytes;
        this.ComponentType = compentType;
    }
    ToBytes() {
        return this.Bytes;
    }
    ToString() {
        switch (this.ComponentType) {
            case exports.Seed:
                return (0, Serialization_1.bytesToBase64)(this.Bytes);
            case exports.Private:
                return (0, Serialization_1.bytesToBase64)(this.Bytes);
            case exports.Public:
                return (0, Serialization_1.Bytes2Hex)(this.Bytes);
            case exports.Symmetric:
                return (0, Serialization_1.bytesToBase64)(this.Bytes);
            case exports.QuantumPrivate:
                throw Error("Not implemented yet");
            case exports.QuantumPublic:
                throw Error("Not implemented yet");
            default:
                throw Error("Unknown component type");
        }
    }
}
exports.SerializedComponent = SerializedComponent;
function toInt16(bytes, offset = 0) {
    const buffer = bytes.buffer;
    const view = new DataView(buffer);
    return view.getInt16(offset, true); // 'true' for little-endian, set to 'false' for big-endian
}
exports.Seed = "Seed";
exports.Private = "Private";
exports.Public = "Public";
exports.Symmetric = "Symmetric";
exports.QuantumPrivate = "QuantumPrivate";
exports.QuantumPublic = "QuantumPublic";
const ComponentKeyType = [
    exports.Seed, // 0
    exports.Private, // 1
    exports.Public, // 2
    exports.Symmetric, // 3
    exports.QuantumPrivate, // 4
    exports.QuantumPublic // 5
];
