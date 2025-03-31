import { WriteValue } from "../../Cryptide/Serialization.js";
import { StringToUint8Array, CreateTideMemory } from "../Cryptide/Serialization.js";
import BaseTideRequest from "./BaseTideRequest.js";

export default class RuleSettingSignRequest extends BaseTideRequest {
    /**
     * @param {string} authFlow 
     */
    constructor(authFlow) {
        super("Rules", "1", authFlow, new Uint8Array());
        this.ruleSettings = null;
        this.previousRuleSetting = null;
        this.previousRuleSettingCert = null;

    }

    /**
     * @param {Uint8Array} ruleSettings 
     */
    setNewRuleSetting(ruleSettings) {
        this.ruleSettings = ruleSettings;
    }

    /**
     * @param {Uint8Array} previousRuleSetting 
     */
    setPreviousRuleSetting(previousRuleSetting) {
        this.previousRuleSetting = previousRuleSetting;
    }

    /**
     * @param {Uint8Array} previousRuleSettingCert 
     */
    setPreviousRuleSettingCert(previousRuleSettingCert) {
        this.previousRuleSettingCert = previousRuleSettingCert;
    }

    /**
     * Serializes the data into a draft format
     */
    serializeDraft() {
        if (this.draft.length === 0) {   
            const ruleSettingsToSign = StringToUint8Array(this.ruleSettings)

            if(this.previousRuleSetting !== null) {
                const markPreviousRulePresent = new Uint8Array([1])
                const draft = CreateTideMemory(markPreviousRulePresent, 4 + markPreviousRulePresent.length + 4 + prevRuleSetting.length + 4 + this.previousRuleSettingCert.length + 4 + txBodyToSign.length)

                const prevRuleSetting = StringToUint8Array(this.prevRuleSetting)
                const prevRuleSettingCert = StringToUint8Array(this.prevRuleSettingCert)
                WriteValue(draft, 1, prevRuleSetting);
                WriteValue(draft, 2, prevRuleSettingCert)
                WriteValue(draft, 3, ruleSettingsToSign);
                this.draft = draft;
            } else {
                this.draft = CreateTideMemory(ruleSettingsToSign, 4 + ruleSettingsToSign.length)
            }
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
