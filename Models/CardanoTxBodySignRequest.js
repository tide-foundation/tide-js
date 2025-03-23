import { SHA512_Digest } from "../Cryptide/Hashing/Hash.js";
import { Serialization } from "../Cryptide/index.js";
import { bytesToBase64, numberToUint8Array, StringToUint8Array, StringFromUint8Array } from "../Cryptide/Serialization.js";
import { CurrentTime } from "../Tools/Utils.js";
import BaseTideRequest from "./BaseTideRequest.js";

export default class CardanonTxBodySignRequest extends BaseTideRequest {
    /**
     * @param {string} authFlow 
     */
    constructor(authFlow) {
        super("CardanoTx", "1", authFlow, new Uint8Array());
        this.cert = null;
        this.txBody = null;
    }

    /**
     * @param {Uint8Array} certificate 
     */
    setInitializationCertificate(certificate) {
        this.cert = certificate;
    }

    /**
     * @param {Uint8Array} contexts 
     */
    setTxBody(txBody) {
        this.txBody = txBody;
    }


    /**
     * Serializes the data into a draft format
     */
    serializeDraft() {
        if (this.draft.length === 0) {
            const outputStream = [];
            outputStream.push(...numberToUint8Array(1));
            outputStream.push(...numberToUint8Array(2));
            outputStream.push(this.cert ? 1 : 0);
            outputStream.push(this.numberOfUserContexts);

            if (this.cert) {
                outputStream.push(...numberToUint8Array(this.cert.length));
                outputStream.push(...this.cert);
            }

            if (this.txBody) {
                outputStream.push(...numberToUint8Array(this.txBody.length));
                outputStream.push(...this.txBody);
            }

            this.draft = new Uint8Array(outputStream);
        }
    }

    /**
     * Generates data to authorize
     * @returns {Promise<Uint8Array>}
     */
    async getDataToAuthorize() {
        this.serializeDraft();
        return super.dataToAuthorize();
    }

    /**
     * @returns {Uint8Array} Draft copy
     */
    getDraft() {
        this.serializeDraft();
        return this.draft.slice();
    }

    /**
     * @param {Uint8Array} draft 
     */
    setDraft(draft) {
        this.draft = draft;
    }
}
