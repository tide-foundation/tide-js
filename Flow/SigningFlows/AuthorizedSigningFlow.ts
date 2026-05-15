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

import BaseTideRequest from "../../Models/BaseTideRequest";
import dVVKSigningFlow from "../SigningFlows/dVVKSigningFlow";
import TideKey from "../../Cryptide/TideKey";
import KeyInfo from "../../Models/Infos/KeyInfo";
import { Models, Tools } from "../..";
import { Doken } from "../../Models/Doken";
import { TideError } from "../../Errors/TideError";
import { TideJsErrorCodes } from "../../Errors/codes";

export function AuthorizedSigningFlow(config: { vendorId: string, token: Doken, sessionKey: TideKey, voucherURL: string, homeOrkUrl: string | null, keyInfo: KeyInfo }) {
    if (!(this instanceof AuthorizedSigningFlow)) {
        throw new Error("The 'AuthorizedSigningFlow' constructor must be invoked with 'new'.")
    }

    if (config.token) {
        if (!config.token.payload.sessionKey.Equals(config.sessionKey.get_public_component())) {
            const dokenFp = String(config.token.payload.sessionKey.Serialize().ToString()).slice(0, 8);
            const suppliedFp = String(config.sessionKey.get_public_component().Serialize().ToString()).slice(0, 8);
            throw new TideError({
                code: TideJsErrorCodes.CRYPTO_SESSION_KEY_MISMATCH,
                displayMessage: `Doken session key (${dokenFp}) does not match supplied session key (${suppliedFp})`,
                source: "Flow/SigningFlows/AuthorizedSigningFlow.ts:31",
            });
        }
    }

    var signingFlow = this;
    signingFlow.vvkId = config.vendorId;
    signingFlow.token = config.token;
    signingFlow.voucherURL = config.voucherURL;

    signingFlow.sessKey = config.sessionKey;

    signingFlow.vvkInfo = config.keyInfo;

    signingFlow.signv2 = async function (tideSerializedRequest: Uint8Array, waitForAll: boolean) {
        const flow = new dVVKSigningFlow(this.vvkId, signingFlow.vvkInfo.UserPublic, signingFlow.vvkInfo.OrkInfo, signingFlow.sessKey, signingFlow.token, this.voucherURL);
        return flow.start(BaseTideRequest.decode(tideSerializedRequest), waitForAll);
    }

    signingFlow.initializeRequest = async function (tideReqToInitialize: Models.BaseTideRequest, waitForAll: boolean) {
        const requestToInitializeDetails = await tideReqToInitialize.getRequestInitDetails();
        const initRequest = new BaseTideRequest(
            "TideRequestInitialization",
            "1",
            "Doken:1",
            Tools.TideMemory.CreateFromArray([
                requestToInitializeDetails.creationTime,
                requestToInitializeDetails.expireTime,
                requestToInitializeDetails.modelId,
                requestToInitializeDetails.draftHash
            ]),
            new Tools.TideMemory()
        );
        const flow = new dVVKSigningFlow(this.vvkId, signingFlow.vvkInfo.UserPublic, signingFlow.vvkInfo.OrkInfo, signingFlow.sessKey, signingFlow.token, this.voucherURL);
        const sig = (await flow.start(initRequest, waitForAll))[0];
        tideReqToInitialize.addCreationSignature(requestToInitializeDetails.creationTime, sig);
    }
}