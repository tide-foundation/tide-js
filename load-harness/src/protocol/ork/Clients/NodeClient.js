// Copied from ork/Ork/Ork/Enclave/js/Clients/NodeClient.js at git 12e9f082 for tide-js load-harness v2.
// Patches:
//   1. Off-path imports removed: GenShardResponse, SetShardResponse,
//      ConvertRememberedResponse, ReservationConfirmation,
//      DeviceConvertResponse. These were only used by methods we do not
//      drive from the cmkOnly password-login load path (account creation,
//      device convert, recovery, etc.).
//   2. Off-path methods stubbed (throw) to keep the class shape but avoid
//      pulling in the off-path Models above: isActive, FindReservers,
//      GetSomeORKs, GetMaxORKs, ReserveUID, DeviceConvert, ConvertPass,
//      ConvertRemembered, DeviceAuthenticate, AuthenticateRemembered,
//      GenShard, UpdateShard, SetShard, Commit, RecoverAccount,
//      FinalizeAccountRecovery.
//   3. On-path methods kept verbatim: Convert, Authenticate.
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

import { Cryptide, Clients } from "@tideorg/js";

const { bytesToBase64 } = Cryptide.Serialization;
const Ed25519PublicComponent = Cryptide.Components.Schemes.Ed25519.Ed25519PublicComponent;
const { Point } = Cryptide.Ed25519;
const ClientBase = Clients.ClientBase;

import PrismConvertResponse from "../Models/KeyAuth/Convert/PrismConvertResponse.js";
import CMKConvertResponse from "../Models/KeyAuth/Convert/CMKConvertResponse.js";
// Off-path imports removed: GenShardResponse, SetShardResponse,
// ConvertRememberedResponse, ReservationConfirmation, DeviceConvertResponse.

export default class NodeClient extends ClientBase {
    /**
     * @param {string} url
     */
    constructor(url) {
        super(url)
        this.enabledTideDH = false;
    }

    async isActive() {
        throw new Error("NodeClient.isActive not ported (off-path)");
    }

    async FindReservers() {
        throw new Error("NodeClient.FindReservers not ported (off-path: account creation)");
    }

    async GetSomeORKs() {
        throw new Error("NodeClient.GetSomeORKs not ported (off-path)");
    }

    async GetMaxORKs() {
        throw new Error("NodeClient.GetMaxORKs not ported (off-path)");
    }

    async ReserveUID() {
        throw new Error("NodeClient.ReserveUID not ported (off-path: account creation)");
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

    async DeviceConvert() {
        throw new Error("NodeClient.DeviceConvert not ported (off-path: device flow)");
    }

    async ConvertPass() {
        throw new Error("NodeClient.ConvertPass not ported (off-path: change-password flow)");
    }

    async ConvertRemembered() {
        throw new Error("NodeClient.ConvertRemembered not ported (off-path: remembered-device flow)");
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

    async DeviceAuthenticate() {
        throw new Error("NodeClient.DeviceAuthenticate not ported (off-path: device flow)");
    }

    async AuthenticateRemembered() {
        throw new Error("NodeClient.AuthenticateRemembered not ported (off-path: remembered-device flow)");
    }

    async GenShard() {
        throw new Error("NodeClient.GenShard not ported (off-path: account creation)");
    }

    async UpdateShard() {
        throw new Error("NodeClient.UpdateShard not ported (off-path: account creation/update)");
    }

    async SetShard() {
        throw new Error("NodeClient.SetShard not ported (off-path: account creation)");
    }

    async Commit() {
        throw new Error("NodeClient.Commit not ported (off-path: account creation)");
    }

    async RecoverAccount() {
        throw new Error("NodeClient.RecoverAccount not ported (off-path: account recovery)");
    }

    async FinalizeAccountRecovery() {
        throw new Error("NodeClient.FinalizeAccountRecovery not ported (off-path: account recovery)");
    }
}
