export default class ClientBase {
    url: string;
    token: any;
    sessionKeyPrivateRaw: any;
    sessionKeyPublicEncoded: any;
    /**
    * @param {string} url
    */
    constructor(url: any);
    /**
     * @param {Object} form
     * @returns {FormData}
     */
    _createFormData(form: any): FormData;
    /**
     * @param {string} endpoint
     * @param {number} timeout
     * @returns {Promise<Response>}
     */
    _get(endpoint: any, timeout?: number, signal?: any): Promise<any>;
    /**
    * Silent get, makes a returns a response without handling response errors.
    * @param {string} endpoint
    * @param {number} timeout
    * @returns {Promise<Response>}
    */
    _getSilent(endpoint: any, timeout?: number, signal?: any): Promise<any>;
    /**
     * @param {string} endpoint
     * @param {FormData} data
     * @returns {Promise<Response>}
     */
    _post(endpoint: any, data: any, timeout?: number): Promise<any>;
    /**
     * @param {string} endpoint
     * @param {FormData} data
     * @returns {Promise<Response>}
     */
    _put(endpoint: any, data: any): Promise<Response>;
    /**
     * @param {string} endpoint
     * @param {Object} data
     * @returns {Promise<Response>}
     */
    _postJSON(endpoint: any, data: any): Promise<Response>;
    /**
     * Post silent returns the response without handling response errors.
     * @param {string} endpoint
     * @param {FormData} data
     * @returns {Promise<Response>}
     */
    _postSilent(endpoint: any, data: any, timeout?: number): Promise<any>;
    /**
     * @param {Response} response
     * @param {string} functionName
     * @param {boolean} throwError
     * @returns {Promise<string>}
     */
    _handleError(response: any, functionName?: string, throwError?: boolean): Promise<any>;
    /**
    * @param {Response} response
    * @returns {Promise<string>}
    */
    _handleErrorSimulator(response: any): Promise<any>;
    /**
     * @param {Uint8Array} sessionKeyPrivate
     * @param {string} sessionKeyPublicEncoded
     * @param {string} token
     * @returns
     */
    AddBearerAuthorization(sessionKeyPrivate: any, sessionKeyPublicEncoded: any, token: any): this;
}
