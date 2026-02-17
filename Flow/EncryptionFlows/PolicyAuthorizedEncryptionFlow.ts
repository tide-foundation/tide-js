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
import { CreateTideMemoryFromArray, numberToUint8Array, StringToUint8Array } from "../../Cryptide/Serialization";
import { CurrentTime } from "../../Tools/Utils";
import BaseTideRequest from "../../Models/BaseTideRequest";
import dVVKSigningFlow from "../SigningFlows/dVVKSigningFlow";
import SerializedField from "../../Models/SerializedField";
import dVVKDecryptionFlow from "../DecryptionFlows/dVVKDecryptionFlow";
import TideKey from "../../Cryptide/TideKey";
import KeyInfo from "../../Models/Infos/KeyInfo";
import PolicyProtectedSerializedField from "../../Models/PolicyProtectedSerializedField";

interface EncryptionFlowConfig {
    vendorId: string;
    token: any; // Doken - constructor function, not a class
    policy: Uint8Array;
    sessionKey: TideKey;
    voucherURL: string;
    homeOrkUrl: string | null;
    keyInfo: KeyInfo;
}

interface DataToEncrypt {
    data: Uint8Array;
    tags: string[];
}

interface DataToDecrypt {
    encrypted: Uint8Array;
    tags: string[];
}

export class PolicyAuthorizedEncryptionFlow {
    vvkId: string;
    token: any;
    sessKey: TideKey;
    voucherURL: string;
    policy: Uint8Array;
    vvkInfo: KeyInfo;

    constructor(config: EncryptionFlowConfig) {
        if (!config.token.payload.sessionKey.Equals(config.sessionKey.get_public_component())) {
            throw Error("Mismatch between session key private and Doken session key public");
        }

        this.vvkId = config.vendorId;
        this.token = config.token;
        this.sessKey = config.sessionKey;
        this.voucherURL = config.voucherURL;
        this.policy = config.policy;
        this.vvkInfo = config.keyInfo;
    }

    async encrypt(datasToEncrypt: DataToEncrypt[]): Promise<Uint8Array[]> {
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

        const encryptionRequest = new BaseTideRequest("PolicyEnabledEncryption", "1", "Policy:1", draft);
        encryptionRequest.addPolicy(this.policy);

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

    async decrypt(datasToDecrypt: DataToDecrypt[]): Promise<Uint8Array[]> {
        // Deserialize all datasToDecrypt + include tags in object
        const deserializedDatas = datasToDecrypt.map(d => {
            const b = PolicyProtectedSerializedField.deserialize(d.encrypted);
            if (b.signature == null) throw Error("Signature must be provided in Tide Serialized Data to an Authorized Decryption");
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
                const entry = CreateTideMemoryFromArray([data.encKey, data.signature, data.timestamp, ...data.tags]);
                return entry;
            } else {
                // decrypt data directly
                const entry = CreateTideMemoryFromArray([data.encFieldChk, data.signature, data.timestamp, ...data.tags]);
                return entry;
            }

        })

        const draft = CreateTideMemoryFromArray(entries);

        const decryptionRequest = new BaseTideRequest("PolicyEnabledDecryption", "1", "Policy:1", draft);
        decryptionRequest.addPolicy(this.policy);

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
}
