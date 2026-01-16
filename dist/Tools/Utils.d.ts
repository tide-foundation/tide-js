export declare const Threshold: number;
export declare const Max: number;
export declare function CurrentTime(): number;
/**
 *
 * @param {OrkInfo[]} orkList_Ref List of ORK infos
 * @param {Promise[]} pre_responses Unresolved Promises
 * @param {string} keyType CMK, CVK?
 * @param {number} number Amount of ORKs to wait for
 * @param {number} amountRequired
 * @param {(0 | 1)[]} bitwise_p
 * @param {*[]} optionalArray
 * @param {number} customTimeout
 * @param {function} customPromiseChecker
 * @returns
 */
export declare function WaitForNumberofORKs(orkList_Ref: any, pre_responses: any, keyType: any, amountRequired?: number, bitwise_p?: any, optionalArray?: any, customTimeout?: any, customPromiseChecker?: any): Promise<{
    fulfilledResponses: any[];
    bitwise: any[];
}>;
/**
 *
 * @param {any[]} array
 * @param {number} targetArraySize
 * @returns {any[]}
 */
export declare function removeRandomElements(array: any, targetArraySize: any): any;
export declare function randBetween(x: any, y: any): any;
/**
 * @param {OrkInfo[]} orks
 */
export declare function sortORKs(orks: any): any;
export declare function randomiseEmails(arr: any): any[];
