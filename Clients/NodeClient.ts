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

import { Encryption } from "../Cryptide/index";
import ClientBase from "./ClientBase";
import { BigIntFromByteArray, ConcatUint8Arrays, CreateTideMemory, CreateTideMemoryFromArray, GetValue, StringToUint8Array, base64ToBytes, bytesToBase64 } from "../Cryptide/Serialization";
import BaseTideRequest from "../Models/BaseTideRequest";
import { Point } from "../Cryptide/Ed25519";

export default class NodeClient extends ClientBase {
    enabledTideDH: boolean;
    DHKey: any;
    orkCacheId: any;

    /**
     * @param {string} url
     */
    constructor(url) {
        super(url)
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
    async EnableTideDH(orkPublic, gSessKey?, sessKey?) {
        if(!this.sessionKeyPrivateRaw) throw Error("Add a session key to the client first");
        this.enabledTideDH = true;
        this.DHKey = await Encryption.DH.computeSharedKey(orkPublic, this.sessionKeyPrivateRaw);
        return this;
    }
    /**
     * @param {number} index 
     * @param {string} vuid 
     * @param {BaseTideRequest} request 
     * @param {string} voucher
     */
    async PreSign(index, vuid, request, voucher) {
        if (!this.enabledTideDH) throw Error("TideDH must be enabled");
        const encrypted = await Encryption.AES.encryptData(CreateTideMemoryFromArray([request.encode()]), this.DHKey);
        const data = this._createFormData(
            {
                'encrypted': encrypted,
                'voucher': voucher
            }
        );

        if(!this.token) data.append("gSessKey", this.sessionKeyPublicEncoded);

        const response = await this._post(`/Authentication/Key/v1/PreSign?vuid=${vuid}`, data);
        const responseData = await this._handleError(response, 'PreSign');
        const decrypted = await Encryption.AES.decryptDataRawOutput(base64ToBytes(responseData), this.DHKey);
        const GRSection = GetValue(decrypted, 0);
        if (GRSection.length % 32 != 0) throw new Error("Unexpected response legnth. Must be divisible by 32");
        let GRis = [];
        for (let i = 0; i < GRSection.length; i += 32) {
            GRis.push(Point.fromBytes(GRSection.slice(i, i + 32)));
        }
        this.orkCacheId = GetValue(decrypted, 2);
        return {
            index,
            data: {
                GRis,
                AdditionalData: GetValue(decrypted, 1)
            }
            
        }
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
        if (!this.enabledTideDH) throw Error("TideDH must be enabled");
        if (!this.orkCacheId) throw Error("Call PreSign first");
        const payload = CreateTideMemoryFromArray([
            request.encode(),
            ConcatUint8Arrays([new Uint8Array([GRs.length]), ...GRs.map(r => r.toRawBytes())]),
            this.orkCacheId
        ]);
        const encrypted = await Encryption.AES.encryptData(payload, this.DHKey);
        const data = this._createFormData(
            {
                'encrypted': encrypted,
                'bitwise': bytesToBase64(bitwise)
            }
        );
        
        if(!this.token) data.append("gSessKey", this.sessionKeyPublicEncoded);

        const response = await this._post(`/Authentication/Key/v1/Sign?vuid=${vuid}`, data);
        const responseData = await this._handleError(response, 'Sign');
        const decrypted = await Encryption.AES.decryptDataRawOutput(base64ToBytes(responseData), this.DHKey);
        const signatureSection = GetValue(decrypted, 0);
        let Sij = [];
        for (let i = 0; i < signatureSection.length; i += 32) {
            Sij.push(BigIntFromByteArray(signatureSection.slice(i, i + 32)));
        }

        delete this.orkCacheId;
        return {
            Sij,
            AdditionalData: GetValue(decrypted, 1)
        }
    }
    /**
     * @param {number} index 
     * @param {string} vuid 
     * @param {BaseTideRequest} request 
     * @param {string} voucher
     */
    async Decrypt(index, vuid, request, voucher){
        if (!this.enabledTideDH) throw Error("TideDH must be enabled");
        const encrypted = await Encryption.AES.encryptData(CreateTideMemoryFromArray([request.encode()]), this.DHKey);
        const data = this._createFormData(
            {
                'encrypted': encrypted,
                'voucher': voucher
            }
        );
        
        if(!this.token) data.append("gSessKey", this.sessionKeyPublicEncoded);

        const response = await this._post(`/Authentication/Key/v1/Decrypt?vuid=${vuid}`, data);
        const responseData = await this._handleError(response, 'Decrypt');
        const decrypted = await Encryption.AES.decryptDataRawOutput(base64ToBytes(responseData), this.DHKey);
        if (decrypted.length % 32 != 0) throw new Error("Unexpected response legnth. Must be divisible by 32");
        let appliedC1s = [];
        for (let i = 0; i < decrypted.length; i += 32) {
            appliedC1s.push(Point.fromBytes(decrypted.slice(i, i + 32)));
        }
        return {
            index,
            appliedC1s
        }

    }

    async CreateCheckoutSession(vendorData, redirectUrl, licensingTier) {
        const licenseRequest = {
            VendorData: vendorData,
            RedirectUri: redirectUrl,
            LicensingTier: licensingTier
        }
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
            console.log("Error getting license details: " + responseData)
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
            console.log("Error getting license details: " + responseData)
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