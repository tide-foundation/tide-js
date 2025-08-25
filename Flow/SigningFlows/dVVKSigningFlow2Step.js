import { EdDSA } from "../../Cryptide/index.js";
import BaseTideRequest from "../../Models/BaseTideRequest.js";
import { Max, Threshold, WaitForNumberofORKs, sortORKs } from "../../Tools/Utils.js";
import NodeClient from "../../Clients/NodeClient.js";
import OrkInfo from "../../Models/Infos/OrkInfo.js";
import { PreSign, Sign as SumS } from "../../Math/KeySigning.js";
import { BigIntToByteArray, ConcatUint8Arrays, bytesToBase64, serializeBitArray } from "../../Cryptide/Serialization.js";
import VoucherFlow from "../VoucherFlows/VoucherFlow.js";
import { Doken } from "../../Models/Doken.js";
import TideKey from "../../Cryptide/TideKey.js";

export default class dVVKSigningFlow2Step {
    /**
     * @param {string} vvkid
     * @param {Point} vvkPublic
     * @param {OrkInfo[]} orks 
     * @param {TideKey} sessKey 
     * @param {Doken} doken 
     * @param {string} voucherURL
     */
    constructor(vvkid, vvkPublic, orks, sessKey, doken, voucherURL) {
        this.vvkid = vvkid;
        this.vvkPublic = vvkPublic;
        this.orks = orks;
        this.orks = sortORKs(this.orks); // sort for bitwise!

        if(doken){
            if(!doken.payload.sessionKey.Equals(sessKey.get_public_component())) throw Error("Mismatch between session key private and Doken session key public");
            this.doken = doken.serialize();
        }        
        this.sessKey = sessKey;
        this.getVouchersFunction = null;

        this.voucherURL = voucherURL;

    }
    /**
     * @param {(request: string) => Promise<string> } getVouchersFunction
     * @returns {dVVKSigningFlow}
     */
    setVoucherRetrievalFunction(getVouchersFunction) {
        this.getVouchersFunction = getVouchersFunction;
        return this;
    }

    async setRequest(request){
        if(!(request instanceof BaseTideRequest)) throw 'Request is not a BaseTideRequest';
        if(request.dyanmicData.length != 0) throw 'Dyanamic data must be null for signing flow 2 step';
        this.request = request;
    }
    /**
     * 
     * @param {Uint8Array | Uint8Array[]} dynamicData 
     * @returns {Promise<Uint8Array[]>}
     */
    async preSign(dynamicData){
        let dynDataisArray = false;
        if(dynamicData){
            if(!(dynamicData instanceof Uint8Array) && !(Array.isArray(dynamicData))) throw 'Dynamic data must be Uint8Array or Uint8Array[]';
            if(dynamicData instanceof Uint8Array){
                this.request.dyanmicData = dynamicData;
            }else dynDataisArray = true;
        }

        const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "vendorsign");
        const pre_vouchers = voucherFlow.GetVouchers(this.getVouchersFunction);

        const pre_clients = this.orks.map(info => new NodeClient(info.orkURL).AddBearerAuthorization(this.sessKey.get_private_component().rawBytes, this.sessKey.get_public_component().Serialize().ToString(), this.doken).EnableTideDH(info.orkPublic));
        const clients = await Promise.all(pre_clients); 

        const { vouchers } = await pre_vouchers;

        const pre_PreSignResponses = clients.map((client, i) => client.PreSign(i, this.vvkid, dynDataisArray ? this.request.replicate().setNewDynamicData(dynamicData[i]) : this.request, vouchers.toORK(i)));
        const { fulfilledResponses, bitwise } = await WaitForNumberofORKs(this.orks, pre_PreSignResponses, "VVK", waitForAll ? Max : Threshold, null, clients);
        const GRj = PreSign(fulfilledResponses.map(f => f.GRis));

        this.preSignState = {
            clients,
            GRj,
            bitwise
        }

        return fulfilledResponses.map(f => f.AdditionalData);
    }
    /**
     * @param {Uint8Array | Uint8Array[]} dynamicData 
     * @returns 
     */
    async sign(dynamicData){
        let dynDataisArray = false;
        if(dynamicData){
            if(!(dynamicData instanceof Uint8Array) && !(Array.isArray(dynamicData))) throw 'Dynamic data must be Uint8Array or Uint8Array[]';
            if(dynamicData instanceof Uint8Array){
                this.request.dyanmicData = dynamicData;
            }else dynDataisArray = true;
        }
        if(!this.preSignState) throw 'Execute preSign first';

        const pre_SignResponses = this.preSignState.clients.map((client, i) => client.Sign(this.vvkid, dynDataisArray ? this.request.replicate().setNewDynamicData(dynamicData[i]) : this.request, this.preSignState.GRj, serializeBitArray(this.preSignState.bitwise)));
        const SignResponses = await Promise.all(pre_SignResponses);
        const Sj = SumS(SignResponses.map(s => s.Sij));

        if (GRj.length != Sj.length) throw Error("Weird amount of GRjs and Sjs");
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
