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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Ed25519SeedComponent = exports.Ed25519PrivateComponent = exports.Ed25519PublicComponent = void 0;
const Ed25519_1 = require("../../../Ed25519");
const Math_1 = require("../../../Math");
const Serialization_1 = require("../../../Serialization");
const BaseComponent_1 = require("../../BaseComponent");
const Ed25519Scheme_1 = __importDefault(require("./Ed25519Scheme"));
class Ed25519PublicComponent extends BaseComponent_1.BasePublicComponent {
    get Scheme() { return Ed25519Scheme_1.default; }
    get ComponentType() { return BaseComponent_1.Public; }
    ;
    constructor(rawData) {
        super();
        /**@type {Uint8Array} */
        this.pb = undefined;
        /**@type {Point} */
        this.p = undefined;
        if (rawData instanceof Ed25519_1.Point) {
            this.p = rawData;
        }
        else if (rawData instanceof Uint8Array) {
            this.pb = rawData;
        }
        else {
            throw Error("unexpected type;");
        }
    }
    get public() {
        if (!this.p && this.pb)
            this.p = Ed25519_1.Point.fromBytes(this.pb);
        else if (!this.p && !this.pb)
            throw Error("empty object");
        return this.p;
    }
    get rawBytes() {
        if (!this.pb && this.p)
            this.pb = this.p.toRawBytes();
        else if (!this.pb && !this.p)
            throw Error("empty object");
        return this.pb;
    }
    AddComponent(component) {
        if (component instanceof Ed25519PublicComponent) {
            return new Ed25519PublicComponent(this.public.add(component.public));
        }
        throw Error("Mismatch with components");
    }
    MultiplyComponent(component) {
        if (component instanceof Ed25519PrivateComponent) {
            return new Ed25519PublicComponent(this.public.mul(component.priv));
        }
        throw Error("Mismatch with components");
    }
    MinusComponent(component) {
        if (component instanceof Ed25519PublicComponent) {
            return new Ed25519PublicComponent(this.public.add(component.public.negate()));
        }
        throw Error("Mismatch with components");
    }
    EqualsComponent(component) {
        if (component instanceof Ed25519PublicComponent) {
            return this.public.equals(component.public);
        }
        throw Error("Mismatch with components");
    }
    SerializeComponent() {
        return this.rawBytes.slice();
    }
}
exports.Ed25519PublicComponent = Ed25519PublicComponent;
Ed25519PublicComponent.Name = "Ed25519PublicComponent";
Ed25519PublicComponent.Version = "1";
class Ed25519PrivateComponent extends BaseComponent_1.BasePrivateComponent {
    get Scheme() { return Ed25519Scheme_1.default; }
    get ComponentType() { return BaseComponent_1.Private; }
    ;
    get priv() {
        if (!this.p && this.rB)
            this.p = (0, Serialization_1.BigIntFromByteArray)(this.rB);
        else if (!this.p && !this.rB)
            throw Error("Empty object");
        return this.p;
    }
    get rawBytes() {
        if (!this.rB && this.p)
            this.rB = (0, Serialization_1.BigIntToByteArray)(this.p);
        else if (!this.rB && !this.p)
            throw Error("Empty object");
        return this.rB;
    }
    constructor(rawData) {
        super();
        /**@type {bigint} */
        this.p = undefined;
        /**@type {Uint8Array} */
        this.rB = undefined;
        if (typeof rawData == "bigint") {
            this.p = rawData;
        }
        else if (rawData instanceof Uint8Array) {
            this.rB = rawData;
        }
        else {
            throw Error("unexpected type;");
        }
    }
    SerializeComponent() {
        return this.rawBytes.slice();
    }
    GetPublic() {
        return new Ed25519PublicComponent(Ed25519_1.Point.BASE.mul(this.priv));
    }
    static New() {
        return Ed25519SeedComponent.New().GetPrivate();
    }
}
exports.Ed25519PrivateComponent = Ed25519PrivateComponent;
Ed25519PrivateComponent.Name = "Ed25519PrivateComponent";
Ed25519PrivateComponent.Version = "1";
class Ed25519SeedComponent extends BaseComponent_1.BaseSeedComponent {
    get Scheme() { return Ed25519Scheme_1.default; }
    get ComponentType() { return BaseComponent_1.Seed; }
    ;
    get rawBytes() {
        return this.rB;
    }
    constructor(rawData) {
        super();
        /**@type {Uint8Array} */
        this.rB = undefined;
        if (rawData instanceof Uint8Array)
            this.rB = rawData.slice();
        else if (!rawData)
            this.rB = Ed25519SeedComponent.GenerateSeed(); // if nothing provided - self instanciate
        else
            throw Error("Expecting Uint8Array or nothing for constructor");
    }
    SerializeComponent() {
        return this.rB.slice();
    }
    static GenerateSeed() {
        const head = Ed25519_1.etc.randomBytes(32);
        head[0] &= 248; // Clamp bits: 0b1111_1000,
        head[31] &= 127; // 0b0111_1111,
        head[31] |= 64; // 0b0100_0000
        return head;
    }
    GetPrivate() {
        return new Ed25519PrivateComponent((0, Math_1.mod)((0, Serialization_1.BigIntFromByteArray)(this.rawBytes)));
    }
    GetPublic() {
        return this.GetPrivate().GetPublic();
    }
    static New() {
        return new Ed25519SeedComponent(this.GenerateSeed());
    }
}
exports.Ed25519SeedComponent = Ed25519SeedComponent;
Ed25519SeedComponent.Name = "Ed25519SeedComponent";
Ed25519SeedComponent.Version = "1";
