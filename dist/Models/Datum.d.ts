export default class Datum {
    data: any;
    tag: any;
    /**
     * @param {string|Uint8Array} Data
     * @param {number} Tag
     */
    constructor(Data: any, Tag: any);
    static fromJSON(json: any): Datum;
    toObject(): {
        Data: string;
        Tag: any;
    };
}
