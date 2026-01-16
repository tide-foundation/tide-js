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
exports.PlainSignatureFormat = exports.TestSignatureFormat = exports.TidecloakSettingsSignatureFormat = exports.AuthorizerSignatureFormat = exports.PublicKeySignatureFormat = exports.ClientURLSignatureFormat = exports.URLSignatureFormat = exports.PolicyAuthorizedTideRequestSignatureFormat = exports.TideSignatureFormat = void 0;
const index_1 = require("../index");
const Serialization_1 = require("../Serialization");
class TideSignatureFormat {
    /**
     * @param {string|Uint8Array} message
     */
    constructor(message) {
        this.Header = () => "=====TIDE_" + this.Name + ":" + this.Version + "_START=====\n";
        this.Footer = () => "\n=====TIDE_" + this.Name + ":" + this.Version + "_END=====";
        if (typeof (message) == 'string') {
            this.Message = (0, Serialization_1.StringToUint8Array)(message);
        }
        else if (message instanceof Uint8Array) {
            this.Message = message.slice();
        }
        else
            throw Error("Unknown type provided");
    }
    /**
     *
     * @returns {Uint8Array}
     */
    format() {
        return (0, Serialization_1.ConcatUint8Arrays)([(0, Serialization_1.StringToUint8Array)(this.Header()), this.Message, (0, Serialization_1.StringToUint8Array)(this.Footer())]);
    }
}
exports.TideSignatureFormat = TideSignatureFormat;
class PolicyAuthorizedTideRequestSignatureFormat extends TideSignatureFormat {
    constructor(issueTimeBytes, exp, modelId, draftHash) {
        const expiry = new Uint8Array(8);
        const expiry_view = new DataView(expiry.buffer);
        expiry_view.setBigInt64(0, exp, true);
        const message = index_1.Serialization.ConcatUint8Arrays([issueTimeBytes, expiry, (0, Serialization_1.StringToUint8Array)(modelId), draftHash]);
        super(message);
        this.Name = "PolicyAuthorizedTideRequest";
        this.Version = "1";
    }
}
exports.PolicyAuthorizedTideRequestSignatureFormat = PolicyAuthorizedTideRequestSignatureFormat;
class URLSignatureFormat extends TideSignatureFormat {
    constructor(message) {
        super(message);
        this.Name = "URL";
        this.Version = "1";
    }
}
exports.URLSignatureFormat = URLSignatureFormat;
class ClientURLSignatureFormat extends TideSignatureFormat {
    constructor(message) {
        super(message);
        this.Name = "ClientURL";
        this.Version = "1";
    }
}
exports.ClientURLSignatureFormat = ClientURLSignatureFormat;
class PublicKeySignatureFormat extends TideSignatureFormat {
    constructor(message) {
        super(message);
        this.Name = "PublicKey";
        this.Version = "1";
    }
}
exports.PublicKeySignatureFormat = PublicKeySignatureFormat;
class AuthorizerSignatureFormat extends TideSignatureFormat {
    constructor(authflow, modelIds, authorizer) {
        const authflow_b = (0, Serialization_1.StringToUint8Array)(authflow);
        const models_b = modelIds.map(k => (0, Serialization_1.StringToUint8Array)(k));
        const authorizer_pack = index_1.Serialization.CreateTideMemory(authflow_b, 8 + (4 * models_b.length) + authflow_b.length + models_b.reduce((sum, next) => sum + next.length, 0) + authorizer.length);
        index_1.Serialization.WriteValue(authorizer_pack, 1, authorizer);
        models_b.forEach((model, i) => {
            index_1.Serialization.WriteValue(authorizer_pack, i + 2, model);
        });
        super(authorizer_pack);
        this.Name = "Authorizer";
        this.Version = "1";
    }
    format() {
        return this.Message.slice();
    }
}
exports.AuthorizerSignatureFormat = AuthorizerSignatureFormat;
class TidecloakSettingsSignatureFormat extends TideSignatureFormat {
    constructor(message) {
        super(message);
        this.Name = "TidecloakSettings";
        this.Version = "1";
    }
}
exports.TidecloakSettingsSignatureFormat = TidecloakSettingsSignatureFormat;
class TestSignatureFormat extends TideSignatureFormat {
    constructor(message) {
        super(message);
        this.Name = "TestMessage";
        this.Version = "1";
    }
}
exports.TestSignatureFormat = TestSignatureFormat;
class PlainSignatureFormat extends TideSignatureFormat {
    /**
     * WARNING: Only use this class if you are SURE that the data you are signing is ALREADY serialized in some form.
     * @param {string|Uint8Array} message
     */
    constructor(message) {
        super(message);
    }
    format() {
        return this.Message.slice();
    }
}
exports.PlainSignatureFormat = PlainSignatureFormat;
