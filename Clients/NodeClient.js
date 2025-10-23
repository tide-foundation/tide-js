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

import { AES, DH } from "../Cryptide/index.js";
import GenShardResponse from "../Models/Responses/KeyGen/GenShard/GenShardResponse.js";
import ClientBase from "./ClientBase.js";
import SetShardResponse from "../Models/Responses/KeyGen/SetShard/SetShardResponse.js";
import PrismConvertResponse from "../Models/Responses/KeyAuth/Convert/PrismConvertResponse.js";
import CMKConvertResponse from "../Models/Responses/KeyAuth/Convert/CMKConvertResponse.js";
import { BigIntFromByteArray, ConcatUint8Arrays, CreateTideMemory, CreateTideMemoryFromArray, GetValue, StringToUint8Array, base64ToBytes, bytesToBase64 } from "../Cryptide/Serialization.js";
import ConvertRememberedResponse from "../Models/Responses/KeyAuth/Convert/ConvertRememberedResponse.js";
import BaseTideRequest from "../Models/BaseTideRequest.js";
import ReservationConfirmation from "../Models/Responses/Reservation/ReservationConfirmation.js";
import { Ed25519PrivateComponent, Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";
import { Point } from "../Cryptide/Ed25519.js";
import TideKey from "../Cryptide/TideKey.js";
import { Doken } from "../Models/Doken.js";
import DeviceConvertResponse from "../Models/Responses/KeyAuth/Convert/DeviceConvertResponse.js";

export default class NodeClient extends ClientBase {
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
     * @param {number} index
     * @param {string} uid
     * @param {string} sessId
     * @param {string} voucher
     * @param {Point} gSessKeyPub
     * @returns 
     */
    async ReserveUID(index, uid, sessId, voucher, gSessKeyPub) {
        const data = this._createFormData({
            "sessId": sessId,
            "voucher": voucher,
            "gSessKeyPub": gSessKeyPub.toBase64()
        })
        const response = await this._post(`/Authentication/Create/ReserveUserId?uid=${uid}`, data);
        const responseData = await this._handleError(response, "Reserve UID");
        return {
            "index": index,
            resConf: ReservationConfirmation.from(responseData)
        };
    }

    /**
     * @param {number} index
     * @param {string} uid 
     * @param {Point} gBlurPass
     * @param {Ed25519PublicComponent} gSessKeyPub
     * @param {boolean} rememberMe
     * @param {boolean} cmkCommitted
     * @param {boolean} prismCommitted
     * @param {string} voucher
     * @param {string} m
     * @returns
     */
    async Convert(index, uid, gBlurPass, gSessKeyPub, rememberMe, voucher, m, cmkCommitted = true, prismCommitted = true) {
        const data = this._createFormData({
            'gBlurPass': gBlurPass.toBase64(),
            'gSessKeyPub': gSessKeyPub.Serialize().ToString(),
            'rememberMe': rememberMe,
            'cmkCommitted': cmkCommitted,
            'prismCommitted': prismCommitted,
            'voucher': voucher,
            'M': m
        })
        const response = await this._post(`/Authentication/Auth/Convert?uid=${uid}`, data)
        const responseData = await this._handleError(response, "Convert CMK/Prism");
        const returnObj = {
            "CMKConvertResponse": CMKConvertResponse.from(responseData.split("|")[0]),
            "PrismConvertResponse": PrismConvertResponse.from(responseData.split("|")[1])
        };
        return {
            "index": index,
            returnObj // only one value is allowed in indexed requests, apart from the index
        }
    }

    /**
     * @param {number} index
     * @param {string} uid 
     * @param {string} gSessKeyPub
     * @param {boolean} rememberMe
     * @param {boolean} cmkCommitted
     * @param {boolean} prismCommitted
     * @param {string} voucher
     * @param {string} m
     * @returns
     */
    async DeviceConvert(index, uid, gSessKeyPub, rememberMe, voucher, m, cmkCommitted = true, prismCommitted = true) {
        const data = this._createFormData({
            'gBlurPass': null,
            'gSessKeyPub': gSessKeyPub,
            'rememberMe': rememberMe,
            'cmkCommitted': cmkCommitted,
            'prismCommitted': prismCommitted,
            'voucher': voucher,
            'M': m
        })
        const response = await this._post(`/Authentication/Auth/Convert?uid=${uid}`, data)
        const responseData = await this._handleError(response, "Device Convert CMK/Prism");
        const returnObj = {
            "DeviceConvertResponse": DeviceConvertResponse.from(responseData)
        };
        return {
            "index": index,
            returnObj // only one value is allowed in indexed requests, apart from the index
        }
    }

    /**
     * @param {number} index 
     * @param {string} uid 
     * @param {Point} gBlurPass 
     * @param {Ed25519PublicComponent} gSessKeyPub 
     * @param {string} voucher
     * @param {string} m
     */
    async ConvertPass(index, uid, gBlurPass, gSessKeyPub, voucher, m) {
        const data = this._createFormData({
            'gBlurPass': gBlurPass.toBase64(),
            'gSessKeyPub': gSessKeyPub.Serialize().ToString(),
            'voucher': voucher,
            'M': m
        })
        const response = await this._post(`/Authentication/Auth/ConvertPass?uid=${uid}`, data)
        const responseData = await this._handleError(response, "ConvertPass CMK/Prism");
        return {
            "index": index,
            "ConvertPassResponse": PrismConvertResponse.from(responseData)
        }
    }

    /**
     * @param {number} index
     * @param {string} uid 
     * @param {string} selfRequesti
     * @param {string} voucher
     * @returns
     */
    async ConvertRemembered(index, uid, selfRequesti, voucher) {
        const data = this._createFormData({
            'selfRequesti': selfRequesti,
            'voucher': voucher
        })
        const response = await this._post(`/Authentication/Auth/ConvertRemembered?uid=${uid}`, data)
        const responseData = await this._handleError(response, "Convert Passwordless");
        return {
            "index": index,
            data: ConvertRememberedResponse.from(responseData)
        };
    }

    /**
     * @param {string} uid 
     * @param {string} selfRequesti
     * @param {bigint} blurHCMKMul
     * @param {Uint8Array} bitwise
     * @param {boolean} cmkCommitted
     * @param {boolean} prismCommitted
     * @returns {Promise<string>}
     */
    async Authenticate(uid, selfRequesti, blurHCMKMul, bitwise, cmkCommitted = true, prismCommitted = true) {
        const data = this._createFormData({
            'selfRequesti': selfRequesti,
            'blurHCMKMul': blurHCMKMul.toString(),
            'bitwise': bytesToBase64(bitwise),
            'cmkCommitted': cmkCommitted,
            'prismCommitted': prismCommitted
        })
        const response = await this._post(`/Authentication/Auth/Authenticate?uid=${uid}`, data)

        const encSig = await this._handleError(response, "Authenticate");
        return encSig;
    }

    /**
     * @param {string} uid 
     * @param {string} prkRequesti
     * @param {bigint} blurHCMKMul
     * @param {Uint8Array} bitwise
     * @returns {Promise<string>}
     */
    async DeviceAuthenticate(uid, prkRequesti, blurHCMKMul, bitwise) {
        const data = this._createFormData({
            'prkRequesti': prkRequesti,
            'blurHCMKMul': blurHCMKMul.toString(),
            'bitwise': bytesToBase64(bitwise)
        })
        const response = await this._post(`/Authentication/Auth/DeviceAuthenticate?uid=${uid}`, data)

        const encSig = await this._handleError(response, "Authenticate");
        return encSig;
    }

    /**
     * 
     * @param {string} uid 
     * @param {bigint} blurHCMKMul 
     * @param {Uint8Array} ORKsBitwise 
     */
    async AuthenticateRemembered(uid, blurHCMKMul, ORKsBitwise) {
        const data = this._createFormData({
            'blurHCMKMul': blurHCMKMul.toString(),
            'bitwise': bytesToBase64(ORKsBitwise),
        })
        const response = await this._post(`/Authentication/Auth/AuthenticateRemembered?uid=${uid}`, data)

        const encSig = await this._handleError(response, "Authenticate");
        return encSig;
    }

    /**
     * @param {number} index
     * @param {string} uid
     * @param {string} voucher
     * @param {string} reservationAuth
     * @param {string} purpose
     * @param {string[]} mIdORKij
     * @param {number} numKeys
     * @param {Point[]} gMultipliers
     * @param {Point} gSessKeyPub
     * @returns {Promise<GenShardResponse>}
     */
    async GenShard(index, uid, voucher, reservationAuth, purpose, mIdORKij, numKeys, gMultipliers, gSessKeyPub) {
        const data = this._createFormData(
            {
                'voucher': voucher,
                'reservationAuth': reservationAuth,
                'purpose': purpose,
                'mIdORKij': mIdORKij,
                'numKeys': numKeys,
                'gMultipliers': gMultipliers.map(p => p == null ? "" : new Ed25519PublicComponent(p).Serialize().ToString()),
                'gSessKeyPub': gSessKeyPub.toBase64()
            }
        );
        const response = await this._post(`/Authentication/Create/GenShard?uid=${uid}`, data);

        const responseData = await this._handleError(response, "GenShard");
        const responseModel = GenShardResponse.from(responseData);
        return {
            index,
            responseModel
        }
    }

    /**
     * @param {number} index
     * @param {string} uid
     * @param {string} purpose
     * @param {Point[]} gMultipliers
     * @param {string} auth
     * @param {Point} gSessKeyPub
     * @returns {Promise<GenShardResponse>}
     */
    async UpdateShard(index, uid, purpose, gMultipliers, auth, gSessKeyPub, tag) {
        const data = this._createFormData(
            {
                'purpose': purpose,
                'gMultipliers': gMultipliers.map(p => p == null ? "" : new Ed25519PublicComponent(p).Serialize().ToString()),
                'auth': auth,
                'gSessKeyPub': gSessKeyPub.toBase64()
            }
        );
        const response = await this._post(`/Authentication/Create/UpdateShard?uid=${uid}`, data);

        const responseData = await this._handleError(response, "UpdateShard");
        const responseModel = GenShardResponse.from(responseData);
        return {
            index,
            tag,
            responseModel
        }
    }

    /**
     * @param {string} uid 
     * @param {string[]} shares 
     * @param {string} encAuthi
     * @param {Point} gSessKeyPub
     * @param {string} keyType
     */
    async SetShard(uid, shares, encAuthi, gSessKeyPub, keyType) {
        const data = this._createFormData(
            {
                'yijCipher': shares,
                'encAuthi': encAuthi,
                'gSessKeyPub': gSessKeyPub.toBase64()
            });
        const response = await this._post(`/Authentication/Create/Set${keyType}?uid=${uid}`, data);

        const responseData = await this._handleError(response, "SendShard");
        return SetShardResponse.from(responseData);
    }


    /**
     * @param {string} uid 
     * @param {bigint} S 
     * @param {Point} gSessKeyPub 
     */
    async Commit(uid, S, gSessKeyPub) {
        const data = this._createFormData(
            {
                'S': S.toString(),
                'gSessKeyPub': gSessKeyPub.toBase64()
            }
        );
        const response = await this._post(`/Authentication/Create/Commit?uid=${uid}`, data);
        const responseData = await this._handleError(response, "Commit");
        if (responseData !== "Key Created") Promise.reject("Commit: Account creation failed");
    }

    /**
     * @param {Point} orkPublic 
     */
    async EnableTideDH(orkPublic) {
        if (!this.sessionKeyPrivateRaw) throw Error("Add a session key to the client first");
        this.enabledTideDH = true;
        this.DHKey = await DH.computeSharedKey(orkPublic, this.sessionKeyPrivateRaw);
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
        const encrypted = await AES.encryptData(CreateTideMemoryFromArray([request.encode()]), this.DHKey);
        const data = this._createFormData(
            {
                'encrypted': encrypted,
                'voucher': voucher
            }
        );

        if (!this.token) data.append("gSessKey", this.sessionKeyPublicEncoded);

        const response = await this._post(`/Authentication/Key/v1/PreSign?vuid=${vuid}`, data);
        const responseData = await this._handleError(response, 'PreSign');
        const decrypted = await AES.decryptDataRawOutput(base64ToBytes(responseData), this.DHKey);
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
        const encrypted = await AES.encryptData(payload, this.DHKey);
        const data = this._createFormData(
            {
                'encrypted': encrypted,
                'bitwise': bytesToBase64(bitwise)
            }
        );

        if (!this.token) data.append("gSessKey", this.sessionKeyPublicEncoded);

        const response = await this._post(`/Authentication/Key/v1/Sign?vuid=${vuid}`, data);
        const responseData = await this._handleError(response, 'Sign');
        const decrypted = await AES.decryptDataRawOutput(base64ToBytes(responseData), this.DHKey);
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
    async Decrypt(index, vuid, request, voucher) {
        if (!this.enabledTideDH) throw Error("TideDH must be enabled");
        const encrypted = await AES.encryptData(CreateTideMemoryFromArray([request.encode()]), this.DHKey);
        const data = this._createFormData(
            {
                'encrypted': encrypted,
                'voucher': voucher
            }
        );

        if (!this.token) data.append("gSessKey", this.sessionKeyPublicEncoded);

        const response = await this._post(`/Authentication/Key/v1/Decrypt?vuid=${vuid}`, data);
        const responseData = await this._handleError(response, 'Decrypt');
        const decrypted = await AES.decryptDataRawOutput(base64ToBytes(responseData), this.DHKey);
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
        })

        const response = await this._post(`/Authentication/AccountRecovery/StartRecovery?aruid=${uid}`, data);
        const responseData = await this._handleError(response, "StartRecovery");
        if (responseData !== "Email sent successfully") throw Error("orks.failedToSendEmail");
        return {
            index: i,
            responseData
        }
    }

    async FinalizeAccountRecovery(uid, channelId) {
        const response = await this._post(`/Authentication/AccountRecovery/CleanUpSession?uid=${uid}&channelId=${channelId}`, {});
        const responseData = await this._handleError(response, "CleanUpRecovery");
        if (responseData !== "Session has been cleaned up") throw Error("orks.errorFinalizingAccountRecovery");
        return { responseData }

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

    // --- Forseti (prod) endpoints: generic, no test data baked in ---

    /** Internal helper: POST JSON and parse JSON body (via your existing error handler). */
    async _postJsonAndParse(path, payload, label) {
        const res = await this._postJSON(path, payload);
        const text = await this._handleError(res, label);
        try { return JSON.parse(text); } catch { return text; }
    }

    /**
     * POST /Forseti/Upload/source
     * Compiles server-side and stores. Returns { bh, entryType }.
     */
    async UploadPolicySource(vendorId, modelId, uploadedBy, entryType, sdkVersion, source) {
        return await this._postJsonAndParse(
            `/Forseti/Upload/source`,
            { vendorId, modelId, uploadedBy, entryType, sdkVersion, source },
            "Forseti Upload Source"
        );
    }

    /**
     * POST /Forseti/Upload/dll
     * Stores a precompiled DLL. Returns { bh, entryType }.
     */
    async UploadPolicyDll(vendorId, modelId, uploadedBy, entryType, sdkVersion, dllBase64) {
        return await this._postJsonAndParse(
            `/Forseti/Upload/dll`,
            { vendorId, modelId, uploadedBy, entryType, sdkVersion, dllBase64 },
            "Forseti Upload DLL"
        );
    }

    /**
     * POST /Forseti/Gate/validate
     * Returns { allowed: boolean, error?: string|null }.
     */
    async ValidateAccess(vvkid, modelId, contractId, resource, action, claims) {
        try {
            const res = await this._postJSON(`/Forseti/Gate/validate`, { vvkid, modelId, contractId, resource, action, claims });
            const text = await this._handleError(res, "Forseti Validate");
            let obj;
            try { obj = JSON.parse(text); } catch { obj = null; }
            if (!obj || typeof obj.allowed !== "boolean") return { allowed: false, error: "BadResponse" };
            if (obj.error && obj.error.length) return { allowed: false, error: obj.error };
            return obj;
        } catch (e) {
            return { allowed: false, error: e?.message || "Validate.Failed" };
        }
    }
    /**
     * GET /Forseti/Meta/sdk-version (plain text)
     */
    async GetForsetiSdkVersion() {
        const res = await this._get(`/Forseti/Meta/sdk-version`);
        const text = await res.text();
        if (!res.ok || !text) throw new Error("Failed to get Forseti SDK version");
        return text.trim();
    }


}