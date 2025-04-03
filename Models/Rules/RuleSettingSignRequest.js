import { WriteValue } from "../../Cryptide/Serialization.js";
import { StringToUint8Array, CreateTideMemory } from "../../Cryptide/Serialization.js";
import BaseTideRequest from "../BaseTideRequest.js";

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
            if(this.previousRuleSetting !== null) {
                const markPreviousRulePresent = new Uint8Array([1])
                const draft = CreateTideMemory(markPreviousRulePresent, 4 + markPreviousRulePresent.length + 4 + this.previousRuleSetting.length + 4 + this.previousRuleSettingCert.length + 4 + this.ruleSettings.length)
                WriteValue(draft, 1, this.previousRuleSetting);
                WriteValue(draft, 2, this.previousRuleSettingCert)
                WriteValue(draft, 3, this.ruleSettings);
                this.draft = draft;
            } else {
                const markPreviousNotRulePresent = new Uint8Array([0])
                const draft = CreateTideMemory(markPreviousNotRulePresent, 4 + markPreviousNotRulePresent.length + 4 + this.ruleSettings.length)
                WriteValue(draft, 1, this.ruleSettings);
                this.draft = draft;
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
