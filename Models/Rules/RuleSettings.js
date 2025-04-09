export default class RuleSettings {
    /**
     * @param {string} data - JSON string
     */
    constructor(data) {
        this.rawString = data;
        try {
            this.object = JSON.parse(this.rawString);
        } catch (e) {
            console.error("Invalid JSON format", e);
            this.object = null;
        }
    }

    /**
     * Returns a formatted JSON object for easy reading.
     */
    toPrettyObject() {
        if (this.object) {
            return this.object
        }
        return "Invalid JSON data";
    }
}
