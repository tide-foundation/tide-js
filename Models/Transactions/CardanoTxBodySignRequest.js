import { SHA512_Digest } from "../../Cryptide/Hashing/Hash.js";
import { Serialization } from "../../Cryptide/index.js";
import { bytesToBase64, numberToUint8Array, StringToUint8Array, StringFromUint8Array, CreateTideMemory } from "../../Cryptide/Serialization.js";
import { CurrentTime } from "../../Tools/Utils.js";
import BaseTideRequest from "../BaseTideRequest.js";

export default class CardanoTxBodySignRequest extends BaseTideRequest {
    /**
     * @param {string} authFlow 
     */
    constructor(authFlow) {
        super("CardanoTx", "1", authFlow, new Uint8Array());
        this.txBody = null;
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
            const txBodyToSign = Serialization.base64ToBytes(this.txBody)
            this.draft = CreateTideMemory(txBodyToSign, 4 + txBodyToSign.length)
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
