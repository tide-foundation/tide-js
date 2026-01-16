export default class EnclaveEntry {
    username: any;
    persona: any;
    expired: any;
    userInfo: any;
    orksBitwise: any;
    selfRequesti: any;
    sessKey: any;
    /**
     * @param {string} username
     * @param {string} persona
     * @param {bigint} expired
     * @param {KeyInfo} userInfo
     * @param {(0|1)[]} orksBitwise
     * @param {string[]} selfRequesti
     * @param {Uint8Array} sessKey
     */
    constructor(username: any, persona: any, expired: any, userInfo: any, orksBitwise: any, selfRequesti: any, sessKey: any);
    toString(): string;
    static from(data: any): EnclaveEntry;
}
