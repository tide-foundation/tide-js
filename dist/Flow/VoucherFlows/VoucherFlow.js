"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const VoucherClient_1 = __importDefault(require("../../Clients/VoucherClient"));
const VoucherResponse_1 = __importDefault(require("../../Models/Responses/Vendor/VoucherResponse"));
const TideKey_1 = __importDefault(require("../../Cryptide/TideKey"));
const Ed25519Scheme_1 = __importDefault(require("../../Cryptide/Components/Schemes/Ed25519/Ed25519Scheme"));
class VoucherFlow {
    /**
     * @param {Point[]} orkPaymentPublics
     * @param {string} voucherURL
     * @param {string} action
     */
    constructor(orkPaymentPublics, voucherURL, action) {
        this.orkPaymentPublics = orkPaymentPublics;
        this.voucherURL = voucherURL;
        this.action = action;
    }
    /**
     * I'm making this so I can use keycloak's client that has all of the keycloak's authorization built in.
     * @param {(request: string) => Promise<string>} clientFunction
     * @returns
     */
    async GetVouchers(clientFunction = null) {
        let vouchers = undefined;
        const k = TideKey_1.default.NewKey(Ed25519Scheme_1.default);
        const blurKeyPub = await k.prepVouchersReq(this.orkPaymentPublics);
        if (clientFunction == null) {
            // get vouchers
            const vendorClient = new VoucherClient_1.default(this.voucherURL);
            vouchers = await vendorClient.GetVouchers(blurKeyPub, this.action, k.get_public_component().public);
        }
        else {
            const request = JSON.stringify({
                BlurPORKi: blurKeyPub.map(blur => blur.toBase64()),
                ActionRequest: this.action,
                BlurerK: k.get_public_component().public.toBase64()
            });
            const response = await clientFunction(request);
            vouchers = VoucherResponse_1.default.from(response, k.get_public_component().public.toBase64());
        }
        return { vouchers, k };
    }
}
exports.default = VoucherFlow;
