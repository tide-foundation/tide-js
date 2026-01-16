export default class TideKey {
    static NewKey(scheme: any): TideKey;
    static FromSerializedComponent(c: any): TideKey;
    /**@type { BaseComponent } */
    component: any;
    privateComponent: any;
    publicComponent: any;
    constructor(c: any);
    /**
     *
     * @returns {BasePrivateComponent}
     */
    get_private_component(): any;
    /**
     * @returns {BasePublicComponent}
     */
    get_public_component(): any;
    sign(message: any): Promise<any>;
    verify(message: any, signature: any): Promise<any>;
    asymmetricDecrypt(cipher: any): Promise<any>;
    asymmetricEncrypt(message: any): Promise<any>;
    prepVouchersReq(gORKn: any): Promise<any[]>;
}
