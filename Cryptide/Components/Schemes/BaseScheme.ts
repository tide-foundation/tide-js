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

import { TideError } from "../../../Errors/TideError";
import { TideJsErrorCodes } from "../../../Errors/codes";

export default class BaseScheme{
    static get Name(): string { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Name not implemented", source: "tide-js/Cryptide/Components/Schemes/BaseScheme.ts:22" }); }
    static GetVerifyingFunction = (): any => { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Verifying function not implemented", source: "tide-js/Cryptide/Components/Schemes/BaseScheme.ts:23" }); }
    static GetSigningFunction = (): any => { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Signing function not implemented", source: "tide-js/Cryptide/Components/Schemes/BaseScheme.ts:24" }); }
    static GetEncryptingFunction = (): any => { throw new TideError({ code: TideJsErrorCodes.CRYPTO_NOT_IMPLEMENTED, displayMessage: "Encrypting function not implemented", source: "tide-js/Cryptide/Components/Schemes/BaseScheme.ts:25" }); }
}
