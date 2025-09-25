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

import NodeClient from "../Clients/NodeClient.js";
import OrkInfo from "../Models/Infos/OrkInfo.js";

import { CommitShardPrep, ProcessShards } from "../Math/KeyGeneration.js";
import { CurrentTime, Max, Threshold, WaitForNumberofORKs, randomiseEmails, sortORKs } from "../Tools/Utils.js";
import { RandomBigInt } from "../Cryptide/Math.js";
import { Point } from "../Cryptide/Ed25519.js";
import { bitArrayAND, bitArrayToUint8Array, bytesToBase64, deserializeBitArray, serializeBitArray, uint8ArrayToBitArray } from "../Cryptide/Serialization.js";
import { AES, DH } from "../Cryptide/index.js";
import VoucherFlow from "./VoucherFlows/VoucherFlow.js";
import NetworkClient from "../Clients/NetworkClient.js";
import SimulatorFlow from "./SimulatorFlow.js";
import { Ed25519PublicComponent } from "../Cryptide/Components/Schemes/Ed25519/Ed25519Components.js";

export default class dKeyGenerationFlow{
    /**
     * TODO Remove gVRK from params
     * @param {string} uid
     * @param {string} gVRK
     * @param {OrkInfo[]} orks 
     * @param {Uint8Array} sessKey
     * @param {Point} gSessKeyPub
     * @param {string} purpose
     * @param {string} voucherURL
     * @param {string[]} emails
     * @param {(0|1)[]} bitwise
     * @param {string[]} selfRequesti
     * @param {Point} userPublic
     * @param {number} expired
     */
    constructor(uid, gVRK, orks, sessKey, gSessKeyPub, purpose, voucherURL, emails=null, bitwise=null, selfRequesti=[], userPublic=null, expired=null) {
        if(expired != null) if(expired < CurrentTime()) throw Error("Time has expired. Try again");
        if(orks.length < Max) throw Error("Not enough orks available to create an account");
        this.uid = uid;
        this.bitwise = bitwise == null ? null : bitwise;
        this.orks = sortORKs(orks);
        this.selfRequesti = selfRequesti;
        this.userPublic = userPublic;
        this.sessKey = sessKey;
        this.gSessKeyPub = gSessKeyPub;
        this.purpose = purpose;
        this.voucherURL = voucherURL;
        this.emails = emails;
        this.getVouchersFunction = null;

        this.savedOrkPublics = this.orks.map(o => o.orkPublic);
        this.orksToWaitFor = purpose == "NEW" ? Max : Threshold;
    }

    static async ReserveUID(uid, voucherURL, gSessKeyPub, homeOrkUrl = null){
        const simClient = new NetworkClient(homeOrkUrl);
        const availableOrks = (await simClient.FindReservers(uid));
        const pre_activeOrks = SimulatorFlow.FilterInactiveOrks(availableOrks);
        const reservers = availableOrks.slice(0, 5); // super unlikely all 5 orks are down
        const voucherFlow = new VoucherFlow(reservers.map(o => o.orkPaymentPublic), voucherURL, "reserve");
        const vouchers = (await voucherFlow.GetVouchers()).vouchers;

        const reserveClients = reservers.map(r => new NodeClient(r.orkURL));

        const pre_ReserveResponses = reserveClients.map((client, i) => client.ReserveUID(i, uid, 'SESSIONID', vouchers.toORK(i), gSessKeyPub))
        const {fulfilledResponses} = await WaitForNumberofORKs(reservers, pre_ReserveResponses, "NEW", 1);
        const lowestProximityresConf = fulfilledResponses.reduce((prev, curr) => (curr.proximity < prev.proximity ? curr : prev)); // get closest proximity

        return {
            reservationConfirmation: lowestProximityresConf.toString(),
            activeOrks: (await pre_activeOrks)
        }
    }

    /**
     * @param {(request: string) => Promise<string> } getVouchersFunction
     * @returns {dKeyGenerationFlow}
     */
    setVoucherRetrievalFunction(getVouchersFunction){
        this.getVouchersFunction = getVouchersFunction;
        return this;
    }

    /**
     * @param {number} numKeys 
     * @param {Point[]} gMultipliers 
     * @param {string} reservationAuth
     */
    async GenShard(numKeys, gMultipliers, reservationAuth=null) {
        const clients = this.orks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        let vouchers;
        if(this.purpose == "NEW"){
            if(reservationAuth == null) throw Error("reservationAuth must not be null for new keys");
            const voucherFlow = new VoucherFlow(this.orks.map(o => o.orkPaymentPublic), this.voucherURL, "signup");
            vouchers = (await voucherFlow.GetVouchers()).vouchers;
        }

        let blurs = [];
        const gBluredMultipliers = gMultipliers.map(gMul => {
            if(gMul != null){
                const b = RandomBigInt();
                blurs.push(b);
                return gMul.mul(b);
            }else{
                blurs.push(null);
                return null;
            }
        })

        const ids = this.orks.map(ork => ork.orkID);
        let count = 0;
        const pre_GenShardResponses = clients.map((client, i) => {
            let auth = "";
            if(this.bitwise != null){
                if(this.bitwise[i] == true){
                    auth = this.selfRequesti[count];
                    count++;
                }
            }
            if(this.purpose == "NEW") return client.GenShard(i, this.uid, vouchers.toORK(i), reservationAuth, this.purpose, ids, numKeys, gBluredMultipliers, this.gSessKeyPub);
            else return client.UpdateShard(i, this.uid, this.purpose, gBluredMultipliers, auth, this.gSessKeyPub, auth == "");
        });

        // create prkECDHi here to save time
        const prkECHi = await DH.generateECDHi(this.orks.map(o => o.orkPublic), this.sessKey);

        const {fulfilledResponses, bitwise} = await WaitForNumberofORKs(
            this.orks, 
            pre_GenShardResponses,
            this.purpose, 
            this.orksToWaitFor, 
            null, 
            prkECHi, 
            null, 
            this.purpose == "NEW" ? null : (result) => {
                if(result.tag == true) return false; // tag == "", inactive ork, don't add to promises to wait for
                else return true; // active ork
            });

        this.gState = {
            bitwise: bitwise,
            keyUse: ["", ""], // not VVK, doesn't matter
            prkECHi,
            ... await ProcessShards(fulfilledResponses, bitwise, this.sessKey)
        };

        const UnblurredGMultipled = this.gState.gMultiplied.map((gMultiplied, i) => {
            if(gMultiplied != null){
                return gMultiplied.public.divide(blurs[i]);
            }else{
                return null;
            }
        });

        return {gMultiplied: UnblurredGMultipled, gK: this.gState.gK}
    }

    /**
     * @param {string} authorizer
     * @param {string} keyType
     */
    async SetShard(authorizer, keyType) {
        if(this.gState == undefined) throw Error("GState is not defined");

        const clients = this.orks.map(ork => new NodeClient(ork.orkURL)) // create node clients
        const randomisedEmails = randomiseEmails(this.emails);

        // No pretty place to put this line 
        const pre_encAuthi = this.gState.prkECHi.map(async (dh, i) => await AES.encryptData(JSON.stringify({
            'GR': this.gState.gR.toBase64(),
            'Auth': authorizer,
            'Email': randomisedEmails[i],
            'InitGVRK_GR': keyType == "VVK" ? this.gState.VRK_gR.map(gr => gr.toBase64()) : [],
        }), dh));
        const encAuthi = await Promise.all(pre_encAuthi);

        const pre_SendShardResponses = clients.map((client, i) => client.SetShard(this.uid, this.gState.sortedShares[i], encAuthi[i], this.gSessKeyPub, keyType))
        const SendShardResponses = await Promise.all(pre_SendShardResponses);

        this.sState = await CommitShardPrep(
            this.uid, 
            SendShardResponses, 
            this.savedOrkPublics, 
            this.gState.timestamp, 
            this.gState.gR, 
            this.userPublic == null ? this.gState.gK : this.userPublic, 
            this.bitwise == null ? this.gState.bitwise : bitArrayAND(this.gState.bitwise, this.bitwise), // given a list of orks that responded to genshard, and a list that were requested to be active, determine the particpating orks
            this.purpose, 
            this.sessKey,
            this.gSessKeyPub,
            keyType == "VVK" ? this.gState.VRK_gR : null,
            keyType == "VVK" ? authorizer : null,
            );
        this.gState = undefined;
        const resp = {
            "VRK_SIGNATURE_TO_STORE": this.sState.vrkSignatureToStore ,
            "M": bytesToBase64(this.sState.M),
            "FIRST_ADMIN": this.sState.firstAdmin
        }
        return resp;
    }

    /**
     */
    async Commit() {
        if(this.sState == undefined) throw Error("SState is undefined");

        const clients = this.orks.map(ork => new NodeClient(ork.orkURL)) // create node clients

        const pre_CommitResponses = clients.map(client => client.Commit(this.uid, this.sState.S, this.sState.gSessKeyPub));
        await Promise.all(pre_CommitResponses);
        
    }
}