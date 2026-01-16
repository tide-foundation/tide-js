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
const Hash_1 = require("../Cryptide/Hashing/Hash");
const index_1 = require("../Cryptide/index");
const Serialization_1 = require("../Cryptide/Serialization");
const TideSignature_1 = require("../Cryptide/Signing/TideSignature");
const Utils_1 = require("../Tools/Utils");
class BaseTideRequest {
    /**
     *
     * @param {string} name
     * @param {string} version
     * @param {string} authFlow
     * @param {Uint8Array} draft
     * @param {Uint8Array} dyanmicData
     */
    constructor(name, version, authFlow, draft, dyanmicData = new Uint8Array()) {
        this.name = name;
        this.version = version;
        this.authFlow = authFlow;
        this.draft = draft.slice();
        this.dyanmicData = dyanmicData.slice();
        this.authorization = new Uint8Array();
        this.authorizerCert = new Uint8Array();
        ;
        this.authorizer = new Uint8Array();
        ;
        this.expiry = BigInt((0, Utils_1.CurrentTime)() + 30); // default is 30s
        this.policy = new Uint8Array();
    }
    id() {
        return this.name + ":" + this.version;
    }
    /**
     * This isn't copying. Just created another BaseTideRequest object that allows you to point each individual field to OTHER sections of memory.
     * If you modify an existing 'replicated' field, you'll also modify the other object you originally replicated.
     */
    replicate() {
        const r = new BaseTideRequest(this.name, this.version, this.authFlow, this.draft, this.dyanmicData);
        r.authorization = this.authorization;
        r.authorizerCert = this.authorizerCert;
        r.authorizer = this.authorizer;
        r.expiry = this.expiry;
        r.policy = this.policy;
        return r;
    }
    /**
     * @param {Uint8Array} d
     */
    setNewDynamicData(d) {
        this.dyanmicData = d;
        return this;
    }
    /**
     *
     * @param {number} timeFromNowInSeconds
     */
    setCustomExpiry(timeFromNowInSeconds) {
        this.expiry = timeFromNowInSeconds;
        return this;
    }
    /**
     * @param {Uint8Array} authorizer
     */
    addAuthorizer(authorizer) {
        this.authorizer = authorizer;
    }
    /**
     *
     * @param {Uint8Array} authorizerCertificate
     */
    addAuthorizerCertificate(authorizerCertificate) {
        this.authorizerCert = authorizerCertificate;
    }
    /**
     *
     * @param {Uint8Array} authorization
     */
    addAuthorization(authorization) {
        this.authorization = authorization;
        return this;
    }
    async dataToAuthorize() {
        return (0, Serialization_1.StringToUint8Array)("<datatoauthorize-" + this.name + ":" + this.version + (0, Serialization_1.bytesToBase64)(await (0, Hash_1.SHA512_Digest)(this.draft)) + this.expiry.toString() + "-datatoauthorize>");
    }
    getInitializedTime() {
        let res = {};
        if (!(0, Serialization_1.TryGetValue)(this.authorization, 0, res))
            throw Error("Creation authorization hasn't been added yet");
        const createdAt_b = index_1.Serialization.GetValue(index_1.Serialization.GetValue(this.authorization, 0), 0);
        const createdAt_view = new DataView(createdAt_b.buffer, createdAt_b.byteOffset, createdAt_b.byteLength);
        const createdAt = createdAt_view.getBigInt64(0, true);
        return createdAt;
    }
    /**
     * Add an approval for this request. To be used for policy auth flow
     * @param {Doken} doken
     * @param {Uint8Array} sig
     */
    addApproval(doken, sig) {
        // Ensure creation authorization has been added
        let res = {};
        if (!(0, Serialization_1.TryGetValue)(this.authorization, 0, res))
            throw Error("Creation authorization hasn't been added yet");
        // Deconstruct existing authorization
        let existingSessKeySigs = [];
        let currentSig = {};
        for (let i = 0; (0, Serialization_1.TryGetValue)((0, Serialization_1.GetValue)(this.authorization, 1), i, currentSig); i++) {
            if (currentSig.result.length == 0)
                continue;
            existingSessKeySigs.push(currentSig.result);
        }
        // Now deconstruct exsiting authorizers (dokens)
        let existingDokens = [];
        let currentDoken = {};
        for (let i = 0; (0, Serialization_1.TryGetValue)(this.authorizer, i, currentDoken); i++) {
            if (currentDoken.result.length == 0)
                continue;
            existingDokens.push(currentDoken.result);
        }
        // Now add the new doken and sig to the deconstructed data then reserialize it into the request
        existingDokens.push((0, Serialization_1.StringToUint8Array)(doken.serialize()));
        existingSessKeySigs.push(sig);
        this.authorization = index_1.Serialization.CreateTideMemoryFromArray([
            (0, Serialization_1.GetValue)(this.authorization, 0),
            index_1.Serialization.CreateTideMemoryFromArray(existingSessKeySigs)
        ]);
        this.authorizer = index_1.Serialization.CreateTideMemoryFromArray(existingDokens);
    }
    encode() {
        if (this.authorizer == null)
            throw Error("Authorizer not added to request");
        if (this.authorizerCert == null)
            throw Error("Authorizer cert not provided");
        if (this.authorization == null)
            throw Error("Authorize this request first with an authorizer");
        const name_b = (0, Serialization_1.StringToUint8Array)(this.name);
        const version_b = (0, Serialization_1.StringToUint8Array)(this.version);
        const authFlow_b = (0, Serialization_1.StringToUint8Array)(this.authFlow);
        const expiry = new Uint8Array(8);
        const expiry_view = new DataView(expiry.buffer);
        expiry_view.setBigInt64(0, this.expiry, true);
        const req = index_1.Serialization.CreateTideMemoryFromArray([
            name_b,
            version_b,
            expiry,
            this.draft,
            authFlow_b,
            this.dyanmicData,
            this.authorizer,
            this.authorization,
            this.authorizerCert,
            this.policy
        ]);
        return req;
    }
    static decode(data) {
        // Read field 0 (name) - this is part of the TideMemory structure
        const name_b = index_1.Serialization.GetValue(data, 0);
        const name = new TextDecoder().decode(name_b);
        // Read all other fields
        const version_b = index_1.Serialization.GetValue(data, 1);
        const version = new TextDecoder().decode(version_b);
        const expiry_b = index_1.Serialization.GetValue(data, 2);
        const expiry_view = new DataView(expiry_b.buffer, expiry_b.byteOffset, expiry_b.byteLength);
        const expiry = expiry_view.getBigInt64(0, true);
        const draft = index_1.Serialization.GetValue(data, 3);
        const authFlow_b = index_1.Serialization.GetValue(data, 4);
        const authFlow = new TextDecoder().decode(authFlow_b);
        const dynamicData = index_1.Serialization.GetValue(data, 5);
        const authorizer = index_1.Serialization.GetValue(data, 6);
        const authorization = index_1.Serialization.GetValue(data, 7);
        const authorizerCert = index_1.Serialization.GetValue(data, 8);
        const policy = index_1.Serialization.GetValue(data, 9);
        // Create a new BaseTideRequest with the decoded data
        const request = new BaseTideRequest(name, version, authFlow, draft, dynamicData);
        // Set the remaining fields
        request.expiry = expiry;
        request.authorizer = authorizer;
        request.authorization = authorization;
        request.authorizerCert = authorizerCert;
        request.policy = policy;
        return request;
    }
    async dataToApprove() {
        const creationTime = index_1.Serialization.GetValue(index_1.Serialization.GetValue(this.authorization, 0), 0);
        const creationSig = index_1.Serialization.GetValue(index_1.Serialization.GetValue(this.authorization, 0), 1);
        const creationMessage = new TideSignature_1.PolicyAuthorizedTideRequestSignatureFormat(creationTime, this.expiry, this.id(), await (0, Hash_1.SHA512_Digest)(this.draft));
        return index_1.Serialization.ConcatUint8Arrays([creationMessage.format(), creationSig]);
    }
}
exports.default = BaseTideRequest;
