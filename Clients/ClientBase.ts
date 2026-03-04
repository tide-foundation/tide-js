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
    url: string;
    token: string;
    sessionKeyPrivateRaw: any;
    sessionKeyPublicEncoded: any;

    constructor(url: string) {
        this.url = url
    }

    _createFormData(form: Object): FormData {
        const formData = new FormData();

        Object.entries(form).forEach(([key, value]) => {
            if (Array.isArray(value)) {
                for (let i = 0; i < value.length; i++) {
                    formData.append(key + "[" + i + "]", value[i] as any)
                }
            }
            else
                formData.append(key, value as any)
        });

        return formData
    }

    async _get(endpoint: string, timeout: number = 20000, signal: AbortSignal = null): Promise<Response> {
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
    */
    async _getSilent(endpoint: string, timeout: number = 20000, signal: AbortSignal = null): Promise<Response> {
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

    async _post(endpoint: string, data: FormData, timeout: number = 20000): Promise<Response> {
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

    async _put(endpoint: string, data: FormData): Promise<Response> {
        return fetch(this.url + endpoint, {
            method: 'PUT',
            body: data
        });
    }

    async _postJSON(endpoint: string, data: Object): Promise<Response> {
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
     */
    async _postSilent(endpoint: string, data: FormData, timeout: number = 20000): Promise<Response> {
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

    async _handleError(response: Response, functionName: string = "", throwError: boolean = false): Promise<string> {
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

    async _handleErrorSimulator(response: Response): Promise<string> {
        var error = "";

        const responseData = await response.text();
        if (!response.ok) error = responseData;

        if (error !== "") return Promise.reject(error);

        return responseData;
    }
    AddBearerAuthorization(sessionKeyPrivate: Uint8Array, sessionKeyPublicEncoded: string, token: string){
        this.sessionKeyPrivateRaw = sessionKeyPrivate;
        this.sessionKeyPublicEncoded = sessionKeyPublicEncoded;
        this.token = token;
        return this;
    }
}