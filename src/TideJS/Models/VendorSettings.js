export default class VendorSettings{
    /**
     * @param {boolean} regOn 
     * @param {boolean} backupOn 
     * @param {string} imageURL 
     * @param {string} logoURL 
     */
    constructor(regOn, backupOn, imageURL, logoURL){
        this.regOn = regOn
        this.backupOn = backupOn
        this.imageURL = imageURL
        this.logoURL = logoURL
    }
    toString(){
        return JSON.stringify({
            RegOn: this.regOn,
            BackupOn: this.backupOn,
            ImageURL: this.imageURL,
            LogoURL: this.logoURL
        });
    }
}