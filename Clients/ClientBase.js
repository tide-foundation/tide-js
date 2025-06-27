// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

export default class ClientBase {
    /**
    * @param {string} url 
    */
    constructor(url) {
        this.url = url
    }

    /**
     * @param {Object} form
     * @returns {FormData}
     */
    _createFormData(form) {
        const formData = new FormData();

        Object.entries(form).forEach(([key, value]) => {
            if (Array.isArray(value)) {
                for (let i = 0; i < value.length; i++) {
                    formData.append(key + "[" + i + "]", value[i])
                }
            }
            else
                formData.append(key, value)
        });

        return formData
    }

    /** 
     * @param {string} endpoint 
     * @param {number} timeout
     * @returns {Promise<Response>}
     */
    async _get(endpoint, timeout = 20000, signal = null) {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        let response;
        try{
            response = await fetch(this.url + endpoint, {
                method: 'GET',
                signal: signal ?? controller.signal
            });
            clearTimeout(id);
        }catch{
            throw Error("enclave.networkFailure")
        }
        if(!response.ok) throw Error("Ork.Exceptions.Network.StatusException");
        return response;
    }

    /** 
    * Silent get, makes a returns a response without handling response errors. 
    * @param {string} endpoint 
    * @param {number} timeout
    * @returns {Promise<Response>}
    */
    async _getSilent(endpoint, timeout = 20000, signal = null) {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        let response;
        try {
            response = await fetch(this.url + endpoint, {
                method: 'GET',
                signal: signal ?? controller.signal
            });
            clearTimeout(id);
        } catch {
            throw Error("enclave.networkFailure")
        }
        if (!response.ok) throw Error("Ork.Exceptions.Network.StatusException");
        return response;
    }

    /** 
     * @param {string} endpoint 
     * @param {FormData} data
     * @returns {Promise<Response>}
     */
    async _post(endpoint, data, timeout = 20000) {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        if(this.token) data.append("token", this.token);

        let response;
        try{
            response = await fetch(this.url + endpoint, {
                method: 'POST',
                body: data,
                signal: controller.signal      
            });
            clearTimeout(id);
        }catch{
            throw Error("enclave.networkFailure")
        }
        if(!response.ok) throw Error("Ork.Exceptions.Network.StatusException");
        return response;
    }

    /** 
     * @param {string} endpoint 
     * @param {FormData} data
     * @returns {Promise<Response>}
     */
    async _put(endpoint, data) {
        return fetch(this.url + endpoint, {
            method: 'PUT',
            body: data
        });
    }

    /** 
     * @param {string} endpoint 
     * @param {Object} data
     * @returns {Promise<Response>}
     */
    async _postJSON(endpoint, data) {
        return fetch(this.url + endpoint, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
    }

    /** 
     * Post silent returns the response without handling response errors. 
     * @param {string} endpoint 
     * @param {FormData} data
     * @returns {Promise<Response>}
     */
    async _postSilent(endpoint, data, timeout = 20000) {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        let response;
        try{
            response = await fetch(this.url + endpoint, {
                method: 'POST',
                body: data,
                signal: controller.signal     
            });
            clearTimeout(id);
        }catch{
            throw Error("enclave.networkFailure")
        }
        return response;
    }

    /**
     * @param {Response} response 
     * @param {string} functionName 
     * @param {boolean} throwError 
     * @returns {Promise<string>}
     */
    async _handleError(response, functionName = "", throwError=false) {
        var error = "";

        const responseData = await response.text();
        if (responseData.split(":")[0] === "--FAILED--") {
            console.error(responseData);
            error = responseData.split(":")[1];
        }

        if (error !== "") {
            if(throwError) throw Error(functionName + " " + error);
            else return Promise.reject(error);
        }

        return responseData;
    }

    /**
    * @param {Response} response 
    * @returns {Promise<string>}
    */
    async _handleErrorSimulator(response) {
        var error = "";

        const responseData = await response.text();
        if (!response.ok) error = responseData;

        if (error !== "") return Promise.reject(error);

        return responseData;
    }
    /**
     * @param {Uint8Array} sessionKeyPrivate
     * @param {string} sessionKeyPublicEncoded
     * @param {string} token 
     * @returns 
     */
    AddBearerAuthorization(sessionKeyPrivate, sessionKeyPublicEncoded, token){
        this.sessionKeyPrivateRaw = sessionKeyPrivate;
        this.sessionKeyPublicEncoded = sessionKeyPublicEncoded;
        this.token = token;
        return this;
    }
}