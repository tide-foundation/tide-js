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
import { Threshold, WaitForNumberofORKs, sortORKs } from "../../Tools/Utils";
import NodeClient from "../../Clients/NodeClient";
import OrkInfo from "../../Models/Infos/OrkInfo";
import { PreSign, Sign as SumS } from "../../Math/KeySigning";
import { BigIntToByteArray, ConcatUint8Arrays, GetValue, bytesToBase64, serializeBitArray } from "../../Cryptide/Serialization";
import VoucherFlow from "../VoucherFlows/VoucherFlow";
import { Doken } from "../../Models/Doken";
import TideKey from "../../Cryptide/TideKey";
import { TideError } from "../../Errors/TideError";
import { TideJsErrorCodes } from "../../Errors/codes";

export default class dVVKSigningFlow2Step {
    vvkid: string;
    vvkPublic: any;
    orks: OrkInfo[];
    sessKey: TideKey;
    doken: string;
    getVouchersFunction: ((request: string) => Promise<string>) | null;
    voucherURL: string;
    vendorAction: string;
    request: BaseTideRequest;
    vouchers: any;
    preSignState: any;

    constructor(vvkid: string, vvkPublic: any, orks: OrkInfo[], sessKey: TideKey, doken: Doken, voucherURL: string) {
        this.vvkid = vvkid;
        this.vvkPublic = vvkPublic;
        this.orks = orks;
        this.orks = sortORKs(this.orks); // sort for bitwise!

        if(doken){
            if(!doken.payload.sessionKey.Equals(sessKey.get_public_component())) {
                const dokenFp = String(doken.payload.sessionKey.Serialize().ToString()).slice(0, 8);
                const suppliedFp = String(sessKey.get_public_component().Serialize().ToString()).slice(0, 8);
                throw new TideError({
                    code: TideJsErrorCodes.CRYPTO_SESSION_KEY_MISMATCH,
                    displayMessage: `Doken session key (${dokenFp}) does not match supplied session key (${suppliedFp})`,
                    source: "Flow/SigningFlows/dVVKSigningFlow2Step.ts:48",
                });
            }
            this.doken = doken.serialize();
        }
        this.sessKey = sessKey;
        this.getVouchersFunction = null;

        this.voucherURL = voucherURL;
        this.vendorAction = "vendorsign";

    }
    setVoucherRetrievalFunction(getVouchersFunction: (request: string) => Promise<string>) {
        this.getVouchersFunction = getVouchersFunction;
        return this;
    }

    async setRequest(request){
        if(!(request instanceof BaseTideRequest)) throw new TideError({
            code: TideJsErrorCodes.VAL_INPUT_SHAPE,
            displayMessage: `Request is not a BaseTideRequest — got ${typeof request}`,
            source: "Flow/SigningFlows/dVVKSigningFlow2Step.ts:64",
        });
        if(request.dyanmicData.length != 0) throw new TideError({
            code: TideJsErrorCodes.VAL_INPUT_SHAPE,
            displayMessage: `Dyanamic data must be null for signing flow 2 step (got length ${request.dyanmicData.length})`,
            source: "Flow/SigningFlows/dVVKSigningFlow2Step.ts:65",
        });
        this.request = request;
    }

    async overrideVoucherAction(action){
        this.vendorAction = action;
    }

    getVouchers(){
        if(!this.vouchers) throw new TideError({
            code: TideJsErrorCodes.VAL_INPUT_SHAPE,
            displayMessage: "Call preSign first",
            source: "Flow/SigningFlows/dVVKSigningFlow2Step.ts:74",
        });
        return this.vouchers;
    }
    async preSign(dynamicData: Uint8Array | Uint8Array[]): Promise<Uint8Array[]> {
        let dynDataisArray = false;
        if(dynamicData){
            if(!(dynamicData instanceof Uint8Array) && !(Array.isArray(dynamicData))) throw new TideError({
                code: TideJsErrorCodes.VAL_INPUT_SHAPE,
                displayMessage: `Dynamic data must be Uint8Array or Uint8Array[] — got ${typeof dynamicData} of ${Array.isArray(dynamicData) ? "Array length " + (dynamicData as any).length : "<unknown>"}`,
                source: "Flow/SigningFlows/dVVKSigningFlow2Step.ts:80",
            });
            if(dynamicData instanceof Uint8Array){
                this.request.setNewDynamicData(dynamicData);
            }else dynDataisArray = true;
        }

        const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, this.vendorAction);
        const pre_vouchers = voucherFlow.GetVouchers(this.getVouchersFunction);

        const pre_clients = this.orks.map(info => new NodeClient(info.orkURL).AddBearerAuthorization(this.sessKey.get_private_component().rawBytes, this.sessKey.get_public_component().Serialize().ToString(), this.doken).EnableTideDH(info.orkPublic));
        const clients = await Promise.all(pre_clients);

        const { vouchers, k } = await pre_vouchers;
        this.vouchers = {
            k,
            ...vouchers
        }

        const pre_PreSignResponses = clients.map((client, i) => client.PreSign(i, this.vvkid, dynDataisArray ? this.request.replicate().setNewDynamicData((dynamicData as Uint8Array[])[i]) : this.request, vouchers.toORK(i)));
        const { fulfilledResponses, bitwise } = await WaitForNumberofORKs(this.orks, pre_PreSignResponses, "VVK", Threshold, null, clients);
        const GRj = PreSign(fulfilledResponses.map(f => f.GRis));

        this.preSignState = {
            clients,
            GRj,
            bitwise
        }

        return fulfilledResponses.map(f => f.AdditionalData);
    }
    async sign(dynamicData: Uint8Array | Uint8Array[]){
        let dynDataisArray = false;
        if(dynamicData){
            if(!(dynamicData instanceof Uint8Array) && !(Array.isArray(dynamicData))) throw new TideError({
                code: TideJsErrorCodes.VAL_INPUT_SHAPE,
                displayMessage: `Dynamic data must be Uint8Array or Uint8Array[] — got ${typeof dynamicData} of ${Array.isArray(dynamicData) ? "Array length " + (dynamicData as any).length : "<unknown>"}`,
                source: "Flow/SigningFlows/dVVKSigningFlow2Step.ts:113",
            });
            if(dynamicData instanceof Uint8Array){
                this.request.setNewDynamicData(dynamicData);
            }else {
                if(dynamicData.length != this.preSignState.clients.length) throw new TideError({
                    code: TideJsErrorCodes.VAL_INPUT_SHAPE,
                    displayMessage: `Supplied dynamic-data array length (${dynamicData.length}) does not match the number of ORK clients (${this.preSignState.clients.length}).`,
                    source: "Flow/SigningFlows/dVVKSigningFlow2Step.ts:147",
                });
                dynDataisArray = true;
            }
        }
        if(!this.preSignState) throw new TideError({
            code: TideJsErrorCodes.VAL_INPUT_SHAPE,
            displayMessage: "Execute preSign first",
            source: "Flow/SigningFlows/dVVKSigningFlow2Step.ts:121",
        });

        const pre_SignResponses = this.preSignState.clients.map((client, i) => client.Sign(this.vvkid, dynDataisArray ? this.request.replicate().setNewDynamicData((dynamicData as Uint8Array[])[i]) : this.request, this.preSignState.GRj, serializeBitArray(this.preSignState.bitwise)));
        const SignResponses = await Promise.all(pre_SignResponses);
        const Sj = SumS(SignResponses.map(s => s.Sij));

        if (this.preSignState.GRj.length != Sj.length) throw new TideError({
            code: TideJsErrorCodes.CRYPTO_GRJ_SJ_LENGTH_MISMATCH,
            displayMessage: `GRj/Sj length mismatch: GRjs=${this.preSignState.GRj.length}, Sjs=${Sj.length}, vvkid=${String(this.vvkid).slice(0, 12)}`,
            source: "Flow/SigningFlows/dVVKSigningFlow2Step.ts:127",
        });
        let sigs = [];
        for (let i = 0; i < this.preSignState.GRj.length; i++) {
            sigs.push(ConcatUint8Arrays([this.preSignState.GRj[i].toRawBytes(), BigIntToByteArray(Sj[i])]));
        }

        return {
            sigs,
            addionalDatas: SignResponses.map(s => s.AdditionalData)
        };
    }
}
