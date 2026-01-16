export default class KeyInfo {
    UserId: any;
    UserPublic: any;
    UserM: any;
    OrkInfo: any;
    /**
     *
     * @param {string} userId
     * @param {Point} userPublic
     * @param {string} userM
     * @param {OrkInfo[]} orkInfo
     */
    constructor(userId: any, userPublic: any, userM: any, orkInfo: any);
    toString(): string;
    toNativeTypeObject(): {
        UserId: any;
        UserPublic: any;
        UserM: any;
        OrkInfos: any;
    };
    static from(data: any): KeyInfo;
    static fromNativeTypeObject(json: any): KeyInfo;
}
