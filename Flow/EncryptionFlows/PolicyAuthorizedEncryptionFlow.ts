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

import { Encryption, Serialization } from "../../Cryptide/index";
import { decryptDataRawOutput, encryptDataRawOutput } from "../../Cryptide/Encryption/AES";
import { CreateTideMemoryFromArray, GetValue, numberToUint8Array, StringToUint8Array, TryGetValue } from "../../Cryptide/Serialization";
import { CurrentTime } from "../../Tools/Utils";
import BaseTideRequest from "../../Models/BaseTideRequest";
import dVVKSigningFlow from "../SigningFlows/dVVKSigningFlow";
import SerializedField from "../../Models/SerializedField";
import dVVKDecryptionFlow from "../DecryptionFlows/dVVKDecryptionFlow";
import TideKey from "../../Cryptide/TideKey";
import KeyInfo from "../../Models/Infos/KeyInfo";
import PolicyProtectedSerializedField from "../../Models/PolicyProtectedSerializedField";
import { Tools } from "../..";
import { TideMemory } from "../../Tools";
import { Doken } from "../../Models/Doken";
import { TideError } from "../../Errors/TideError";
import { TideJsErrorCodes } from "../../Errors/codes";

interface EncryptionFlowConfig {
    vendorId: string;
    token: Doken;
    sessionKey: TideKey;
    voucherURL: string;
    homeOrkUrl: string | null;
    keyInfo: KeyInfo;
}

export interface DataToEncrypt {
    data: Uint8Array;
    tags: string[];
}

export interface DataToDecrypt {
    encrypted: Uint8Array;
    tags: string[];
}

export class PolicyAuthorizedEncryptionFlow {
    vvkId: string;
    token: Doken;
    sessKey: TideKey;
    voucherURL: string;
    policy: Uint8Array;
    vvkInfo: KeyInfo;

    constructor(config: EncryptionFlowConfig) {
        if (!config.token.payload.sessionKey.Equals(config.sessionKey.get_public_component())) {
            const dokenFp = String(config.token.payload.sessionKey.Serialize().ToString()).slice(0, 8);
            const suppliedFp = String(config.sessionKey.get_public_component().Serialize().ToString()).slice(0, 8);
            throw new TideError({
                code: TideJsErrorCodes.CRYPTO_SESSION_KEY_MISMATCH,
                displayMessage: `Doken session key (${dokenFp}) does not match supplied session key (${suppliedFp})`,
                source: "Flow/EncryptionFlows/PolicyAuthorizedEncryptionFlow.ts:62",
            });
        }

        this.vvkId = config.vendorId;
        this.token = config.token;
        this.sessKey = config.sessionKey;
        this.voucherURL = config.voucherURL;
        this.vvkInfo = config.keyInfo;
    }

    async createEncryptionRequest(datasToEncrypt: DataToEncrypt[], addHeavyDataToReq = false) {
        const encReqs = await Promise.all(datasToEncrypt.map(async d => {
            const d_b = d.data;
            if (d_b.length < 32) {
                const tags_b = d.tags.map(t => StringToUint8Array(t));

                // if data is less than 32B
                // Gr. EncryptedData
                const encryptedData = await Encryption.ElGamal.encryptDataRaw_withAuthentication(d_b, this.vvkInfo.UserPublic, Serialization.ConcatUint8Arrays(tags_b));

                return {
                    encryptionToSign: encryptedData.cipher,
                    encryptionAuthData: encryptedData.auth,
                    encryptedData: encryptedData.cipher,
                    tags: tags_b,
                    sizeLessThan32: true
                };

            } else {
                const tags_b = d.tags.map(t => StringToUint8Array(t));

                // if data is more than 32B
                const largeDataKey = window.crypto.getRandomValues(new Uint8Array(32));
                const encryptedData = await encryptDataRawOutput(d_b, largeDataKey);
                const encryptedKey = await Encryption.ElGamal.encryptDataRaw_withAuthentication(largeDataKey, this.vvkInfo.UserPublic, Serialization.ConcatUint8Arrays(tags_b));

                return {
                    encryptionToSign: encryptedKey.cipher,
                    encryptionAuthData: encryptedKey.auth,
                    encryptedData: encryptedData,
                    tags: tags_b,
                    sizeLessThan32: false
                };
            }
        }));

        // Start signing flow to authorize this encryption
        const timestamp = CurrentTime();
        const timestamp_b = numberToUint8Array(timestamp, 8);

        let arr = [timestamp_b];

        encReqs.forEach((enc) => {
            const entry = CreateTideMemoryFromArray([
                enc.encryptionToSign.slice(0, 32), // only get C1 point for draft
                enc.encryptionAuthData,
                ...enc.tags])
            arr.push(entry);
        })

        const draft = CreateTideMemoryFromArray(arr);
        const request = new BaseTideRequest("PolicyEnabledEncryption", "1", "Policy:1", draft);

        if (addHeavyDataToReq) {
            request.setCustomExpiry(604800); // default one week - assuming this req is drafted

            // we need to store the actual encrypted data (if size larger than 32) in request as well
            // this is for when we create the PolicyProtectedSerializedField object after committion
            const dataToStoreLater = Serialization.CreateTideMemoryFromArray(encReqs.map((e) =>
                PolicyProtectedSerializedField.create(
                    e.encryptedData,
                    timestamp,
                    e.sizeLessThan32 ? null : e.encryptionToSign,
                    null))); // no signature for now
            request.addAuthorizerCertificate(dataToStoreLater); // authorizer cert not used by the tide network in this flow but useful for us to serialize the data for local storage
        }

        return { request, encReqs, timestamp };
    }

    async encrypt(datasToEncrypt: DataToEncrypt[], policy: Uint8Array): Promise<Uint8Array[]> {
        const { request: encryptionRequest, encReqs, timestamp } = await this.createEncryptionRequest(datasToEncrypt);
        encryptionRequest.addPolicy(policy);

        // Initiate signing flow
        const encryptingSigningFlow = new dVVKSigningFlow(this.vvkId, this.vvkInfo.UserPublic, this.vvkInfo.OrkInfo, this.sessKey, this.token, this.voucherURL);
        const signatures = await encryptingSigningFlow.start(encryptionRequest);

        // Construct final serialized payloads for client to store
        return signatures.map((sig, i) =>
            PolicyProtectedSerializedField.create(
                encReqs[i].encryptedData,
                timestamp,
                encReqs[i].sizeLessThan32 ? null : encReqs[i].encryptionToSign,
                sig)
        )
    }

    async commitEncrypt(request: Uint8Array, policy: Uint8Array) {
        // Remove authorizer cert from request before sending it up to the orks
        const readyEncRequest = BaseTideRequest.decode(request);
        const encryptedData = readyEncRequest.authorizerCert;
        readyEncRequest.authorizerCert = new Tools.TideMemory(); // clear request of the heavy data

        // Deserialize data stored in the request previously
        let encryptedDatas = []
        let resultObj = { result: undefined };
        for (let i = 0; Serialization.TryGetValue(encryptedData, i, resultObj); i++) {
            encryptedDatas.push(resultObj.result);
        }
        const deserializedDatas = encryptedDatas.map(e => {
            const b = PolicyProtectedSerializedField.deserialize(e);
            if (b.signature != null) throw Error("There shouldn't be any signatures in this data");
            return b;
        })

        // Add the policy to the request
        readyEncRequest.addPolicy(policy);

        // Initiate signing flow
        const encryptingSigningFlow = new dVVKSigningFlow(this.vvkId, this.vvkInfo.UserPublic, this.vvkInfo.OrkInfo, this.sessKey, this.token, this.voucherURL);
        const signatures = await encryptingSigningFlow.start(readyEncRequest);

        // Construct final serialized payloads for client to store WITH SIGNATURE - that's the only reason we are doing this again
        return signatures.map((sig, i) =>
            PolicyProtectedSerializedField.create(
                deserializedDatas[i].encFieldChk,
                deserializedDatas[i].timestamp,
                deserializedDatas[i].encKey ? deserializedDatas[i].encKey : null,
                sig)
        )

    }

    createDecryptionRequest(datasToDecrypt: DataToDecrypt[], addHeavyDataToReq=false) {
        // Deserialize all datasToDecrypt + include tags in object
        const deserializedDatas = datasToDecrypt.map(d => {
            const b = PolicyProtectedSerializedField.deserialize(d.encrypted);
            if (b.signature == null) throw new TideError({
                code: TideJsErrorCodes.VAL_INPUT_SHAPE,
                displayMessage: "The data you are trying to decrypt is missing its authorization signature and cannot be decrypted. Please refresh and try again, or contact support if the problem persists.",
                source: "Flow/EncryptionFlows/PolicyAuthorizedEncryptionFlow.ts:208",
                details: [
                    {
                        displayMessage: "PolicyProtectedSerializedField.deserialize returned a record with no `signature` field",
                        code: `encryptedSize=${(d.encrypted as Uint8Array)?.byteLength ?? "<unknown>"} tags=${JSON.stringify(d.tags)}`,
                    },
                ],
            });
            const tags_b = d.tags.map(t => StringToUint8Array(t));
            return {
                ...b,
                tags: tags_b
            }
        })

        // Get orks to apply vvk
        const entries = deserializedDatas.map((data, i) => {
            if (data.encKey) {
                // We must decrypt the encrypted key, not the data itself
                const entry = CreateTideMemoryFromArray([
                    data.encKey.slice(0, 32), // only send c1 (point)
                    data.signature,
                    data.timestamp,
                    ...data.tags]);

                return entry;
            } else {
                // decrypt data directly
                const entry = CreateTideMemoryFromArray([
                    data.encFieldChk.slice(0, 32), // only send c1 (point)
                    data.signature,
                    data.timestamp,
                    ...data.tags]);
                return entry;
            }

        })

        const draft = CreateTideMemoryFromArray(entries);
        const request = new BaseTideRequest("PolicyEnabledDecryption", "1", "Policy:1", draft);
        if(addHeavyDataToReq) {
            request.setCustomExpiry(604800); // default for now - assuming this req is drafted
            const dynData = TideMemory.CreateFromArray(deserializedDatas.map(d => {
                return TideMemory.CreateFromArray([d.encFieldChk, d.encKey ? d.encKey: new Uint8Array()]);
            })) // efficient serialized of heavy data
            request.addAuthorizerCertificate(dynData); // authorizer cert not used by the tide network in this flow but useful for us to serialize the data for local storage
        }

        return { request, deserializedDatas };
    }

    async decrypt(datasToDecrypt: DataToDecrypt[], policy: Uint8Array): Promise<Uint8Array[]> {
        const { request: decryptionRequest, deserializedDatas } = this.createDecryptionRequest(datasToDecrypt);
        decryptionRequest.addPolicy(policy);

        const flow = new dVVKDecryptionFlow(this.vvkId, this.vvkInfo.UserPublic, this.vvkInfo.OrkInfo, this.sessKey, this.token, this.voucherURL);
        const dataKeys = await flow.start(decryptionRequest);

        // Decrypt all datas
        const decryptedDatas = await Promise.all(deserializedDatas.map(async (data, i) => {
            // if encKey exists - decrypt with elgamal that
            // then decrypt encField with key
            if (data.encKey) {
                const key = await decryptDataRawOutput(data.encKey.slice(32), dataKeys[i]);
                return await decryptDataRawOutput(data.encFieldChk, key);
            } else {
                // else - decrypt encField with elgamal
                return await decryptDataRawOutput(data.encFieldChk.slice(32), dataKeys[i]);
            }
        }));

        // Return as bytes
        return decryptedDatas;
    }

    async commitDecrypt(request: Uint8Array, policy: Uint8Array) {
        const decryptionRequest = BaseTideRequest.decode(request);
        decryptionRequest.addPolicy(policy);
        const heavyData = decryptionRequest.authorizerCert;
        decryptionRequest.authorizerCert = new TideMemory(); // clear decryption request of heavy data

        const flow = new dVVKDecryptionFlow(this.vvkId, this.vvkInfo.UserPublic, this.vvkInfo.OrkInfo, this.sessKey, this.token, this.voucherURL);
        const dataKeys = await flow.start(decryptionRequest);

        // Decrypt all datas
        let resultObj = {result:undefined};
        let decryptedDatas = [];
        for(let i = 0; TryGetValue(heavyData, i, resultObj); i++){
            const encFieldChk = GetValue(resultObj.result, 0);
            const encKey = GetValue(resultObj.result, 1);

            // if encKey exists - decrypt with elgamal that
            // then decrypt encField with key
            if (encKey.length > 0) {
                const key = await decryptDataRawOutput(encKey.slice(32), dataKeys[i]);
                decryptedDatas.push(await decryptDataRawOutput(encFieldChk, key));
            } else {
                // else - decrypt encField with elgamal
                decryptedDatas.push(await decryptDataRawOutput(encFieldChk.slice(32), dataKeys[i]));
            }
        }

        // Return as bytes
        return decryptedDatas;
    }
}
