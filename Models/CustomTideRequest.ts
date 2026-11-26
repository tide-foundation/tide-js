import { StringFromUint8Array, StringToUint8Array } from "../Cryptide/Serialization";
import { TideMemory } from "../Tools/TideMemory";
import BaseTideRequest from "./BaseTideRequest";

export class BasicCustomRequest extends BaseTideRequest {
    id(): string {
        return `BasicCustom<${this.name}>:BasicCustom<${this.version}>`;
    }
}

export class DynamicPayloadCustomRequest extends BaseTideRequest {
    id(): string {
        return `DynamicCustom<${this.name}>:DynamicCustom<${this.version}>`;
    }
}

export class DynamicPayloadApprovedCustomRequest extends BaseTideRequest {
    customInfo: CustomInfo | undefined;

    constructor(name: string, version: string, authFlow: string, humanReadableName: string, additionalInfo: any, dyanmicData: Uint8Array) {
        const customInfo = {
            humanReadableName: humanReadableName,
            additionalInfo: additionalInfo
        }
        super(name, version, authFlow, StringToUint8Array(JSON.stringify(customInfo)), dyanmicData);
    }

    id(): string {
        return `DynamicApprovedCustom<${this.name}>:DynamicApprovedCustom<${this.version}>`;
    }

    getAdditionalInfoSupplied(): any {
        if (this.draft.length > 0) return JSON.parse(StringFromUint8Array(this.draft))["additionalInfo"];
        else return null;
    }
}
interface CustomInfo {
    humanReadableName: string;
    additionalInfo: any;
}