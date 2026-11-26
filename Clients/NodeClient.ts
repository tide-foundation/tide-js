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
import { TideError } from "../Errors/TideError";
import { TideJsErrorCodes } from "../Errors/codes";

export default class NodeClient extends ClientBase {
    enabledTideDH: boolean;
    DHKey: any;
    orkCacheId: any;

    constructor(url: string) {
        super(url)
        this.enabledTideDH = false;
    }

    async isActive() {
        const response = await this._get("/active", 3000);
        const responseData = await this._handleError(response, "Is Active");
        return responseData;
    }

    async EnableTideDH(orkPublic: Point, gSessKey?, sessKey?) {
        if (!this.sessionKeyPrivateRaw) throw new TideError({
            code: TideJsErrorCodes.VAL_MISSING_SESSION_KEY,
            displayMessage: "Add a session key to the client first",
            source: "Clients/NodeClient.ts:EnableTideDH",
        });
        this.enabledTideDH = true;
        this.DHKey = await Encryption.DH.computeSharedKey(orkPublic, this.sessionKeyPrivateRaw);
        return this;
    }
    async PreSign(index: number, vuid: string, request: BaseTideRequest, voucher: string) {
        if (!this.enabledTideDH) throw new TideError({
            code: TideJsErrorCodes.VAL_MISSING_SESSION_KEY,
            displayMessage: "TideDH must be enabled",
            source: "Clients/NodeClient.ts:PreSign",
        });
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
        if (GRSection.length % 32 != 0) throw new TideError({
            code: TideJsErrorCodes.PARSE_UNKNOWN_FORMAT,
            displayMessage: "Unexpected response length. Must be divisible by 32",
            source: "Clients/NodeClient.ts:PreSign",
        });
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

    async Sign(vuid: string, request: BaseTideRequest, GRs: Point[], bitwise: Uint8Array, sessId?: Uint8Array) {
        if (!this.enabledTideDH) throw new TideError({
            code: TideJsErrorCodes.VAL_MISSING_SESSION_KEY,
            displayMessage: "TideDH must be enabled",
            source: "Clients/NodeClient.ts:Sign",
        });
        if (!this.orkCacheId) throw new TideError({
            code: TideJsErrorCodes.VAL_MISSING_SESSION_KEY,
            displayMessage: "Call PreSign first",
            source: "Clients/NodeClient.ts:Sign",
        });
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
    async Decrypt(index: number, vuid: string, request: BaseTideRequest, voucher: string){
        if (!this.enabledTideDH) throw new TideError({
            code: TideJsErrorCodes.VAL_MISSING_SESSION_KEY,
            displayMessage: "TideDH must be enabled",
            source: "Clients/NodeClient.ts:Decrypt",
        });
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
        if (decrypted.length % 32 != 0) throw new TideError({
            code: TideJsErrorCodes.PARSE_UNKNOWN_FORMAT,
            displayMessage: "Unexpected response length. Must be divisible by 32",
            source: "Clients/NodeClient.ts:Decrypt",
        });
        let appliedC1s = [];
        for (let i = 0; i < decrypted.length; i += 32) {
            appliedC1s.push(Point.fromBytes(decrypted.slice(i, i + 32)));
        }
        return {
            index,
            appliedC1s
        }

    }

}
