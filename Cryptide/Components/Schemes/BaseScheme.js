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

export default class BaseScheme{
    static get Name() { throw Error("Name not implemented"); }
    /**@returns {(msg: Uint8Array, signature: Uint8Array, pub: BasePublicComponent) => Promise<(boolean)>} */
    static GetVerifyingFunction = () => { throw Error("Verifying function not implemented"); }
    /**@returns {(msg: Uint8Array, priv: BasePrivateComponent) => Promise<(Uint8Array)>} */
    static GetSigningFunction = () => { throw Error("Signing function not implemented"); }
    static GetEncryptingFunction = () => { throw Error("Encrypting function not implemented"); }
}