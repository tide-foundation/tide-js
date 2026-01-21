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

import { BaseComponent, BasePrivateComponent, BasePublicComponent, Seed } from "./Components/BaseComponent";
import { Registery } from "./Components/ComponentRegistry";
import BaseScheme from "./Components/Schemes/BaseScheme";
import { Ed25519SeedComponent } from "./Components/Schemes/Ed25519/Ed25519Components";
import Ed25519Scheme from "./Components/Schemes/Ed25519/Ed25519Scheme";
import { SchemeType } from "./Components/Schemes/SchemeRegistry";
import { computeSharedKey } from "./Encryption/DH";
import { GetPublic, mod, RandomBigInt } from "./Math";
import { BigIntFromByteArray, BigIntToByteArray, Bytes2Hex, bytesToBase64 } from "./Serialization";

export default class TideKey{

    static NewKey(scheme){
        const seedFactory = Registery[scheme.Name][Seed];
        return new TideKey(seedFactory.Create(undefined));
    }

    static FromSerializedComponent(c){
        return new TideKey(BaseComponent.DeserializeComponent(c));
    }
    
    /**@type { BaseComponent } */
    component = undefined;
    privateComponent;
    publicComponent;

    constructor(c){
        if(c instanceof BaseComponent) this.component = c;
        else throw Error("Expecting object derived from BaseComponent");
    }
    /**
     * 
     * @returns {BasePrivateComponent}
     */
    get_private_component(){
        if(!hasOwnInstanceMethod(this.component, "GetPrivate") && !(this.component instanceof BasePrivateComponent)) throw Error("Cannot generate or find private component");
        this.privateComponent = this.component instanceof BasePrivateComponent ? this.component : this.component.GetPrivate();
        return this.privateComponent;
    }
    /**
     * @returns {BasePublicComponent}
     */
    get_public_component(){
        if(!hasOwnInstanceMethod(this.component, "GetPublic") && !(this.component instanceof BasePublicComponent)) throw Error("Cannot generate or find public component");
        this.publicComponent = this.component instanceof BasePublicComponent ? this.component : this.component.GetPublic();
        return this.publicComponent;
    }

    async sign(message){
        const f = this.component.Scheme.GetSigningFunction();
        return await f(message, this.get_private_component());
    }
    async verify(message, signature){
        const f = this.component.Scheme.GetVerifyingFunction();
        return await f(message, signature, this.get_public_component());
    }
    async asymmetricDecrypt(cipher){
        const d = this.component.Scheme.GetDecryptingFunction();
        return await d(cipher, this.get_private_component());
    }
    async asymmetricEncrypt(message){
        const e = this.component.Scheme.GetEncryptingFunction();
        return await e(message, this.get_public_component());
    }
    

    async prepVouchersReq(gORKn){
        // Ensure scheme is Ed25519 for tide vouchers
        if(this.component.Scheme !== Ed25519Scheme) throw Error("Cannot execute prepVouchersReq on a non Ed25519 key");
        let blurKeyPub = [];
        for(let i = 0; i< gORKn.length; i++){
            const z = mod(BigIntFromByteArray(await computeSharedKey(gORKn[i], this.get_private_component().priv)));
            blurKeyPub[i] = gORKn[i].mul(z);
        }
        return blurKeyPub;
    }
}

function hasOwnInstanceMethod(obj, methodName) {
    // get the “own” prototype of this object’s class
    const proto = Object.getPrototypeOf(obj);
    // check it has its own property of that name, and that it’s a function
    return Object.prototype.hasOwnProperty.call(proto, methodName)
        && typeof proto[methodName] === 'function';
}