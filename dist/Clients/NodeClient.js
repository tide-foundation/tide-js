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
const index_1 = require("../Cryptide/index");
const ClientBase_1 = __importDefault(require("./ClientBase"));
const Serialization_1 = require("../Cryptide/Serialization");
const Ed25519_1 = require("../Cryptide/Ed25519");
class NodeClient extends ClientBase_1.default {
    /**
     * @param {string} url
     */
    constructor(url) {
        super(url);
        this.enabledTideDH = false;
    }
    async isActive() {
        const response = await this._get("/active", 3000);
        const responseData = await this._handleError(response, "Is Active");
        return responseData;
    }
    /**
     * @param {Point} orkPublic
     */
    async EnableTideDH(orkPublic, gSessKey, sessKey) {
        if (!this.sessionKeyPrivateRaw)
            throw Error("Add a session key to the client first");
        this.enabledTideDH = true;
        this.DHKey = await index_1.DH.computeSharedKey(orkPublic, this.sessionKeyPrivateRaw);
        return this;
    }
    /**
     * @param {number} index
     * @param {string} vuid
     * @param {BaseTideRequest} request
     * @param {string} voucher
     */
    async PreSign(index, vuid, request, voucher) {
        if (!this.enabledTideDH)
            throw Error("TideDH must be enabled");
        const encrypted = await index_1.AES.encryptData((0, Serialization_1.CreateTideMemoryFromArray)([request.encode()]), this.DHKey);
        const data = this._createFormData({
            'encrypted': encrypted,
            'voucher': voucher
        });
        if (!this.token)
            data.append("gSessKey", this.sessionKeyPublicEncoded);
        const response = await this._post(`/Authentication/Key/v1/PreSign?vuid=${vuid}`, data);
        const responseData = await this._handleError(response, 'PreSign');
        const decrypted = await index_1.AES.decryptDataRawOutput((0, Serialization_1.base64ToBytes)(responseData), this.DHKey);
        const GRSection = (0, Serialization_1.GetValue)(decrypted, 0);
        if (GRSection.length % 32 != 0)
            throw new Error("Unexpected response legnth. Must be divisible by 32");
        let GRis = [];
        for (let i = 0; i < GRSection.length; i += 32) {
            GRis.push(Ed25519_1.Point.fromBytes(GRSection.slice(i, i + 32)));
        }
        this.orkCacheId = (0, Serialization_1.GetValue)(decrypted, 2);
        return {
            index,
            data: {
                GRis,
                AdditionalData: (0, Serialization_1.GetValue)(decrypted, 1)
            }
        };
    }
    /**
     *
     * @param {string} vuid
     * @param {BaseTideRequest} request
     * @param {Point[]} GRs
     * @param {Uint8Array} bitwise
     * @param {Uint8Array} sessId
     */
    async Sign(vuid, request, GRs, bitwise, sessId) {
        if (!this.enabledTideDH)
            throw Error("TideDH must be enabled");
        if (!this.orkCacheId)
            throw Error("Call PreSign first");
        const payload = (0, Serialization_1.CreateTideMemoryFromArray)([
            request.encode(),
            (0, Serialization_1.ConcatUint8Arrays)([new Uint8Array([GRs.length]), ...GRs.map(r => r.toRawBytes())]),
            this.orkCacheId
        ]);
        const encrypted = await index_1.AES.encryptData(payload, this.DHKey);
        const data = this._createFormData({
            'encrypted': encrypted,
            'bitwise': (0, Serialization_1.bytesToBase64)(bitwise)
        });
        if (!this.token)
            data.append("gSessKey", this.sessionKeyPublicEncoded);
        const response = await this._post(`/Authentication/Key/v1/Sign?vuid=${vuid}`, data);
        const responseData = await this._handleError(response, 'Sign');
        const decrypted = await index_1.AES.decryptDataRawOutput((0, Serialization_1.base64ToBytes)(responseData), this.DHKey);
        const signatureSection = (0, Serialization_1.GetValue)(decrypted, 0);
        let Sij = [];
        for (let i = 0; i < signatureSection.length; i += 32) {
            Sij.push((0, Serialization_1.BigIntFromByteArray)(signatureSection.slice(i, i + 32)));
        }
        delete this.orkCacheId;
        return {
            Sij,
            AdditionalData: (0, Serialization_1.GetValue)(decrypted, 1)
        };
    }
    /**
     * @param {number} index
     * @param {string} vuid
     * @param {BaseTideRequest} request
     * @param {string} voucher
     */
    async Decrypt(index, vuid, request, voucher) {
        if (!this.enabledTideDH)
            throw Error("TideDH must be enabled");
        const encrypted = await index_1.AES.encryptData((0, Serialization_1.CreateTideMemoryFromArray)([request.encode()]), this.DHKey);
        const data = this._createFormData({
            'encrypted': encrypted,
            'voucher': voucher
        });
        if (!this.token)
            data.append("gSessKey", this.sessionKeyPublicEncoded);
        const response = await this._post(`/Authentication/Key/v1/Decrypt?vuid=${vuid}`, data);
        const responseData = await this._handleError(response, 'Decrypt');
        const decrypted = await index_1.AES.decryptDataRawOutput((0, Serialization_1.base64ToBytes)(responseData), this.DHKey);
        if (decrypted.length % 32 != 0)
            throw new Error("Unexpected response legnth. Must be divisible by 32");
        let appliedC1s = [];
        for (let i = 0; i < decrypted.length; i += 32) {
            appliedC1s.push(Ed25519_1.Point.fromBytes(decrypted.slice(i, i + 32)));
        }
        return {
            index,
            appliedC1s
        };
    }
    /**
     * @param {number} i
     * @param {string} uid
     * @param {Point} gSessKeyPub
     * @param {bigint} channelId
     * @param {string} homeOrkUrl
     * @param {string} voucher
     */
    async RecoverAccount(i, uid, gSessKeyPub, channelId, homeOrkUrl, voucher) {
        const data = this._createFormData({
            'gSessKeyPub': gSessKeyPub.toBase64(),
            'homeOrkUrl': homeOrkUrl,
            'channelId': channelId.toString(),
            'voucher': voucher
        });
        const response = await this._post(`/Authentication/AccountRecovery/StartRecovery?aruid=${uid}`, data);
        const responseData = await this._handleError(response, "StartRecovery");
        if (responseData !== "Email sent successfully")
            throw Error("orks.failedToSendEmail");
        return {
            index: i,
            responseData
        };
    }
    async FinalizeAccountRecovery(uid, channelId) {
        const response = await this._post(`/Authentication/AccountRecovery/CleanUpSession?uid=${uid}&channelId=${channelId}`, {});
        const responseData = await this._handleError(response, "CleanUpRecovery");
        if (responseData !== "Session has been cleaned up")
            throw Error("orks.errorFinalizingAccountRecovery");
        return { responseData };
    }
    async CreateCheckoutSession(vendorData, redirectUrl, licensingTier) {
        const licenseRequest = {
            VendorData: vendorData,
            RedirectUri: redirectUrl,
            LicensingTier: licensingTier
        };
        return await this._postJSON(`/Payer/License/CreateCheckoutSession`, licenseRequest);
    }
    async IsLicenseActive(vendorId) {
        const response = await this._getSilent(`/Payer/License/IsLicenseActive?obfGVVK=${vendorId}`);
        const text = await response.text();
        const isActive = text.trim().toLowerCase() === 'true';
        return isActive;
    }
    async GetLicenseDetails(vendorId, timestamp, timestampSig) {
        const data = this._createFormData({
            "timestamp": timestamp,
            "timestampSig": timestampSig
        });
        const response = await this._postSilent(`/Payer/License/getLicenseDetails?obfGVVK=${vendorId}`, data);
        const responseData = await response.text();
        if (responseData.startsWith("--FAILED--")) {
            console.log("Error getting license details: " + responseData);
            return;
        }
        return responseData;
    }
    async GetSubscriptionStatus(vendorId, initialSessionId, timestamp, timestampSig) {
        const data = this._createFormData({
            "initialSessionId": initialSessionId,
            "timestamp": timestamp,
            "timestampSig": timestampSig
        });
        const response = await this._postSilent(`/Payer/License/GetSubscriptionStatus?obfGVVK=${vendorId}`, data);
        const responseData = await response.text();
        if (responseData.startsWith("--FAILED--")) {
            console.log("Error getting license details: " + responseData);
            return;
        }
        const status = responseData.toLowerCase() === "active" ? "upcoming renewal" : responseData.toLowerCase();
        return status;
    }
    async CreateCustomerPortalSession(vendorId, redirectUrl, timestamp, timestampSig) {
        const data = this._createFormData({
            "vendorId": vendorId,
            "timestamp": timestamp,
            "timestampSig": timestampSig,
            "redirectUrl": redirectUrl
        });
        return await this._postSilent(`/Payer/License/CreateCustomerPortalSession?obfGVVK=${vendorId}`, data);
    }
    async UpdateSubscription(updateRequest, licenseId, timestamp, timestampSig) {
        const data = this._createFormData({
            "updateRequest": JSON.stringify(updateRequest),
            "licenseId": licenseId,
            "timestamp": timestamp,
            "timestampSig": timestampSig
        });
        return await this._postSilent(`/Payer/License/updateSubscription`, data);
    }
    async CancelSubscription(licenseId, initialSessionId, timestamp, timestampSig) {
        const data = this._createFormData({
            "licenseId": licenseId,
            "initialSessionId": initialSessionId,
            "timestamp": timestamp,
            "timestampSig": timestampSig
        });
        return await this._postSilent(`/Payer/License/CancelSubscription`, data);
    }
}
exports.default = NodeClient;
