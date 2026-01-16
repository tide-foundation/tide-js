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

import { Serialization } from "../index";
import { ConcatUint8Arrays, StringToUint8Array } from "../Serialization";

export class TideSignatureFormat{
    Name: any;
    Version: any;
    Message: any;
    Header = () => "=====TIDE_" + this.Name + ":" + this.Version + "_START=====\n";
    Footer = () => "\n=====TIDE_" + this.Name + ":" + this.Version + "_END=====";
    /**
     * @param {string|Uint8Array} message
     */
    constructor(message){
        if(typeof(message) == 'string'){
            this.Message = StringToUint8Array(message);
        }else if(message instanceof Uint8Array) {
            this.Message = message.slice();
        }else throw Error("Unknown type provided");
    }
    /**
     * 
     * @returns {Uint8Array}
     */
    format(){
        return ConcatUint8Arrays([StringToUint8Array(this.Header()), this.Message, StringToUint8Array(this.Footer())]);
    }
}

export class PolicyAuthorizedTideRequestSignatureFormat extends TideSignatureFormat
{
	Name = "PolicyAuthorizedTideRequest";
	Version = "1";
    constructor(issueTimeBytes, exp, modelId, draftHash){
        const expiry = new Uint8Array(8);
        const expiry_view = new DataView(expiry.buffer);
        expiry_view.setBigInt64(0, exp, true);

        const message = Serialization.ConcatUint8Arrays([issueTimeBytes, expiry, StringToUint8Array(modelId), draftHash]);
        super(message);
    }	
}

export class URLSignatureFormat extends TideSignatureFormat{
    Name = "URL";
    Version = "1";
    constructor(message){
        super(message);
    }
}
export class ClientURLSignatureFormat extends TideSignatureFormat{
    Name = "ClientURL";
    Version = "1";
    constructor(message){
        super(message);
    }
}

export class PublicKeySignatureFormat extends TideSignatureFormat{
    Name = "PublicKey";
    Version = "1";
    constructor(message){
        super(message);
    }
}

export class AuthorizerSignatureFormat extends TideSignatureFormat{
    Name = "Authorizer";
    Version = "1";
    constructor(authflow, modelIds, authorizer){
        const authflow_b = StringToUint8Array(authflow);
        const models_b = modelIds.map(k => StringToUint8Array(k));
        const authorizer_pack = Serialization.CreateTideMemory(authflow_b, 
            8 + (4 * models_b.length) + authflow_b.length + models_b.reduce((sum, next) => sum + next.length, 0) + authorizer.length
        );
        Serialization.WriteValue(authorizer_pack, 1, authorizer);
        models_b.forEach((model, i) => {
            Serialization.WriteValue(authorizer_pack, i + 2, model);
        });
        super(authorizer_pack);
    }
    format(){
        return this.Message.slice();
    }
}

export class TidecloakSettingsSignatureFormat extends TideSignatureFormat{
    Name = "TidecloakSettings";
    Version = "1";
    constructor(message){
        super(message);
    }
}

export class TestSignatureFormat extends TideSignatureFormat{
    Name = "TestMessage";
    Version = "1";
    constructor(message){
        super(message);
    }
}

export class PlainSignatureFormat extends TideSignatureFormat{
    /**
     * WARNING: Only use this class if you are SURE that the data you are signing is ALREADY serialized in some form.
     * @param {string|Uint8Array} message 
     */
    constructor(message){
        super(message);
    }
    format(){
        return this.Message.slice();
    }
}