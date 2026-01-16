import TideKey from "../../Cryptide/TideKey";
export default class VoucherFlow {
    /**
     * @param {Point[]} orkPaymentPublics
     * @param {string} voucherURL
     * @param {string} action
     */
    constructor(orkPaymentPublics: any, voucherURL: any, action: any);
    /**
     * I'm making this so I can use keycloak's client that has all of the keycloak's authorization built in.
     * @param {(request: string) => Promise<string>} clientFunction
     * @returns
     */
    GetVouchers(clientFunction?: any): Promise<{
        vouchers: any;
        k: TideKey;
    }>;
}
