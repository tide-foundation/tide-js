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
const BaseComponent_1 = require("./Components/BaseComponent");
const ComponentRegistry_1 = require("./Components/ComponentRegistry");
const Ed25519Scheme_1 = __importDefault(require("./Components/Schemes/Ed25519/Ed25519Scheme"));
const DH_1 = require("./Encryption/DH");
const Math_1 = require("./Math");
const Serialization_1 = require("./Serialization");
class TideKey {
    static NewKey(scheme) {
        const seedFactory = ComponentRegistry_1.Registery[scheme.Name][BaseComponent_1.Seed];
        return new TideKey(seedFactory.Create(undefined));
    }
    static FromSerializedComponent(c) {
        return new TideKey(BaseComponent_1.BaseComponent.DeserializeComponent(c));
    }
    constructor(c) {
        /**@type { BaseComponent } */
        this.component = undefined;
        if (c instanceof BaseComponent_1.BaseComponent)
            this.component = c;
        else
            throw Error("Expecting object derived from BaseComponent");
    }
    /**
     *
     * @returns {BasePrivateComponent}
     */
    get_private_component() {
        if (!hasOwnInstanceMethod(this.component, "GetPrivate") && !(this.component instanceof BaseComponent_1.BasePrivateComponent))
            throw Error("Cannot generate or find private component");
        this.privateComponent = this.component instanceof BaseComponent_1.BasePrivateComponent ? this.component : this.component.GetPrivate();
        return this.privateComponent;
    }
    /**
     * @returns {BasePublicComponent}
     */
    get_public_component() {
        if (!hasOwnInstanceMethod(this.component, "GetPublic") && !(this.component instanceof BaseComponent_1.BasePublicComponent))
            throw Error("Cannot generate or find public component");
        this.publicComponent = this.component instanceof BaseComponent_1.BasePublicComponent ? this.component : this.component.GetPublic();
        return this.publicComponent;
    }
    async sign(message) {
        const f = this.component.Scheme.GetSigningFunction();
        return await f(message, this.get_private_component());
    }
    async verify(message, signature) {
        const f = this.component.Scheme.GetVerifyingFunction();
        return await f(message, signature, this.get_public_component());
    }
    async asymmetricDecrypt(cipher) {
        const d = this.component.Scheme.GetDecryptingFunction();
        return await d(cipher, this.get_private_component());
    }
    async asymmetricEncrypt(message) {
        const e = this.component.Scheme.GetEncryptingFunction();
        return await e(message, this.get_public_component());
    }
    async prepVouchersReq(gORKn) {
        // Ensure scheme is Ed25519 for tide vouchers
        if (this.component.Scheme !== Ed25519Scheme_1.default)
            throw Error("Cannot execute prepVouchersReq on a non Ed25519 key");
        let blurKeyPub = [];
        for (let i = 0; i < gORKn.length; i++) {
            const z = (0, Math_1.mod)((0, Serialization_1.BigIntFromByteArray)(await (0, DH_1.computeSharedKey)(gORKn[i], this.get_private_component().priv)));
            blurKeyPub[i] = gORKn[i].mul(z);
        }
        return blurKeyPub;
    }
}
exports.default = TideKey;
function hasOwnInstanceMethod(obj, methodName) {
    // get the “own” prototype of this object’s class
    const proto = Object.getPrototypeOf(obj);
    // check it has its own property of that name, and that it’s a function
    return Object.prototype.hasOwnProperty.call(proto, methodName)
        && typeof proto[methodName] === 'function';
}
