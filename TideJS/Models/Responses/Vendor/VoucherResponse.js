
export default class VoucherResponse{
    /**
     * 
     * @param {string[]} voucherPacks 
     * @param {string} qPub 
     * @param {string} payerPub 
     * @param {string} YHat
     * @param {string} blurerK
     * @param {string} UDeObf
     */
    constructor(voucherPacks, qPub, payerPub, Yhat, blurerK, UDeObf){
        this.voucherPacks = voucherPacks;
        this.qPub = qPub;
        this.payerPub = payerPub;
        this.Yhat = Yhat;
        this.blurerK = blurerK;
        this.UDeObf = UDeObf;
    }

    static from(data, blurerK){
        const json = JSON.parse(data);
        return new VoucherResponse(json.voucherPacks, json.QPub, json.PayerPub, json.YHat, blurerK, json.UDeObf);
    }

    /**
     * 
     * @param {number} index 
     * @returns 
     */
    toORK(index){
        return JSON.stringify({
            VoucherPack: this.voucherPacks[index],
            YHat: this.Yhat,
            QPub: this.qPub,
            BlurerK: this.blurerK,
            PayerPublic: this.payerPub
        });
    }
}