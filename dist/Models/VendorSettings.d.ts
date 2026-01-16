export default class VendorSettings {
    regOn: any;
    backupOn: any;
    imageURL: any;
    logoURL: any;
    /**
     * @param {boolean} regOn
     * @param {boolean} backupOn
     * @param {string} imageURL
     * @param {string} logoURL
     */
    constructor(regOn: any, backupOn: any, imageURL: any, logoURL: any);
    toString(): string;
}
