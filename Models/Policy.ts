import { TideMemory } from "../Tools/TideMemory";
import { BigIntToByteArray, BigIntFromByteArray, StringFromUint8Array, StringToUint8Array } from "../Cryptide/Serialization";
import { TideError } from "../Errors/TideError";
import { TideJsErrorCodes } from "../Errors/codes";

export enum ApprovalType {
    EXPLICIT,
    IMPLICIT
}
export enum ExecutionType {
    PRIVATE,
    PUBLIC
}
export class Policy {
    static latestVersion: string = "3";
    version: string;
    contractId: string;
    modelIds: string[];
    keyId: string;
    approvalType: ApprovalType;
    executionType: ExecutionType;
    params: PolicyParameters;
    expiry: bigint | undefined;

    dataToVerify: TideMemory | undefined;
    signature: Uint8Array | undefined;

    constructor(data: { version: string, contractId: string, modelId: string[] | string, keyId: string, approvalType: ApprovalType, executionType: ExecutionType, params: Map<string, any> | PolicyParameters, expiry?: bigint | number }) {
        if (typeof data["version"] !== "string") throw 'Version is not a string';
        // if Policy is constructed directly (not via a subclass), enforce latest version
        if(new.target === Policy){
            if(data["version"] !== Policy.latestVersion){
                throw 'Breaking changes made to Policies. Update how you create a policy in your application'
            } 
        }

        this.version = data["version"];

        if (typeof data["contractId"] !== "string") throw 'ContractId is not a string';
        this.contractId = data["contractId"];
        if (!Array.isArray(data["modelId"]) && typeof data["modelId"] !== "string") throw 'ModelId is not a string';
        this.modelIds = typeof data["modelId"] === "string" ? [data["modelId"]] : data["modelId"];
        if (typeof data["keyId"] !== "string") throw 'KeyId is not a string';
        this.keyId = data["keyId"];

        this.approvalType = data.approvalType;
        this.executionType = data.executionType;

        if (!data["params"]) throw 'Params is null';
        this.params = data["params"] instanceof PolicyParameters ? data["params"] : new PolicyParameters(data["params"]);

        this.expiry = data["expiry"] === undefined ? undefined : BigInt(data["expiry"]);

        this.dataToVerify = this.buildTideMemory();
    }

    private buildTideMemory(): TideMemory {
        const sections: Uint8Array[] = [
            StringToUint8Array(this.version),
            StringToUint8Array(this.contractId),
            TideMemory.CreateFromArray(this.modelIds.map(i => StringToUint8Array(i))),
            StringToUint8Array(this.keyId),
            StringToUint8Array(ApprovalType[this.approvalType]),
            StringToUint8Array(ExecutionType[this.executionType]),
            this.params.toBytes()
        ];

        // only appended when set, so a policy without an expiry serialises as it did before
        if (this.expiry !== undefined) {
            const buffer = new Uint8Array(8);
            new DataView(buffer.buffer).setBigInt64(0, this.expiry, true);
            sections.push(buffer);
        }

        return TideMemory.CreateFromArray(sections);
    }

    hasExpired(): boolean {
        return this.expiry !== undefined && this.expiry < BigInt(Math.floor(Date.now() / 1000));
    }

    static from(data: Uint8Array): Policy {
        const d = new TideMemory(data.length);
        d.set(data);

        const dataToVerify = d.GetValue(0);
        const version = StringFromUint8Array(dataToVerify.GetValue(0));
        if (version != Policy.latestVersion) {
            // old version
            switch (version) {
                case PolicyV1.thisVersion:
                    return PolicyV1.from(d);
                case PolicyV2.thisVersion:
                    return PolicyV2.from(d);
                default:
                    throw new TideError({ code: TideJsErrorCodes.MODEL_VERSION_MISMATCH, displayMessage: `Unknown policy version: ${version}`, source: "tide-js/Models/Policy.ts:75" });
            }
        }

        const contractId = StringFromUint8Array(dataToVerify.GetValue(1));
        const modelIdSection = dataToVerify.GetValue(2);
        const modelIds = []
        let returnObj = {result: undefined}
        for(let i = 0; modelIdSection.TryGetValue(i, returnObj); i++){
            modelIds.push(StringFromUint8Array(returnObj.result))
        }
        const keyId = StringFromUint8Array(dataToVerify.GetValue(3));
        const approvalType: ApprovalType = ApprovalType[StringFromUint8Array(dataToVerify.GetValue(4)) as keyof typeof ApprovalType];
        const executionType: ExecutionType = ExecutionType[StringFromUint8Array(dataToVerify.GetValue(5)) as keyof typeof ExecutionType];

        const params = new PolicyParameters(dataToVerify.GetValue(6));

        const expiry = Policy.readOptionalExpiry(dataToVerify);

        const p = new Policy({
            version,
            contractId,
            modelId: modelIds,
            keyId,
            approvalType,
            executionType,
            params,
            expiry
        });

        const sigRes = { result: undefined };
        if (d.TryGetValue(1, sigRes)) {
            p.signature = sigRes.result;
        }
        return p;
    }

    private static readOptionalExpiry(dataToVerify: TideMemory): bigint | undefined {
        const returnObj = { result: undefined as Uint8Array | undefined };
        if (!dataToVerify.TryGetValue(7, returnObj)) return undefined;

        const expiry = returnObj.result;
        if (!expiry || expiry.length === 0) return undefined;
        if (expiry.length !== 8) throw new TideError({ code: TideJsErrorCodes.MODEL_VERSION_MISMATCH, displayMessage: `Policy expiry must be 8 bytes, got ${expiry.length}`, source: "tide-js/Models/Policy.ts" });

        return new DataView(expiry.buffer, expiry.byteOffset, 8).getBigInt64(0, true);
    }

    toBytes() {
        let d: Uint8Array[] = [this.buildTideMemory()];

        if (this.signature) d.push(this.signature);

        return TideMemory.CreateFromArray(d);
    }
}

export class PolicyParameters {
    entries: Map<string, any>;
    constructor(data: Map<string, any> | Uint8Array) {
        if (data instanceof Uint8Array) {
            this.entries = PolicyParameters.fromBytes(data);
        } else {
            this.entries = new Map(data);
        }
    }

    private static fromBytes(data: Uint8Array): Map<string, any> {
        let params = new Map();
        let i = 0;
        const value = { result: undefined as TideMemory | undefined };

        // Create TideMemory instance to access TryGetValue
        const tideData = new TideMemory(data.length);
        tideData.set(data);

        // Try to get values at sequential indices
        while (tideData.TryGetValue(i, value)) {
            const nameBytes = value.result!.GetValue(0);
            const name = StringFromUint8Array(nameBytes);

            const typeBytes = value.result!.GetValue(1);
            const type = StringFromUint8Array(typeBytes);

            const dataBytes = value.result!.GetValue(2);

            let datum: any;
            switch (type) {
                case "str":
                    datum = StringFromUint8Array(dataBytes);
                    break;
                case "num":
                    const numView = new DataView(dataBytes.buffer, dataBytes.byteOffset, dataBytes.byteLength);
                    datum = numView.getInt32(0, true); // little-endian
                    break;
                case "bnum":
                    // Convert bytes to BigInt (little-endian)
                    datum = BigIntFromByteArray(dataBytes);
                    break;
                case "bln":
                    datum = dataBytes[0] === 1;
                    break;
                case "byt":
                    datum = new Uint8Array(dataBytes);
                    break;
                default:
                    throw new TideError({ code: TideJsErrorCodes.MODEL_UNKNOWN_PARAM_TYPE, displayMessage: `PolicyParameters.fromBytes: could not find type of ${type}`, source: "tide-js/Models/Policy.ts:176" });
            }

            params.set(name, datum);
            i++;
        }
        return params;
    }

    tryGetParameter<T extends string | number | bigint | boolean | Uint8Array>(key: string): [boolean, T]{
        try{
            return [true, this.getParameter(key)];
        }catch{
            return [false, null];
        }
    }

    getParameter<T extends string | number | bigint | boolean | Uint8Array>(key: string): T {
        if (!this.entries.has(key)) {
            throw new TideError({ code: TideJsErrorCodes.MODEL_PARAM_NOT_FOUND, displayMessage: `PolicyParameters.getParameter: parameter '${key}' not found`, source: "tide-js/Models/Policy.ts:195" });
        }

        const value = this.entries.get(key);
        const actualType = value instanceof Uint8Array ? 'Uint8Array' : typeof value;

        // Type checking logic
        let expectedType: string;
        if ((value as any) instanceof Uint8Array) {
            expectedType = 'Uint8Array';
        } else {
            expectedType = typeof value;
        }

        // Validate the type matches what was requested
        // We can't directly check T at runtime, so we infer from the value type
        const isCorrectType =
            (typeof value === 'string' && value.constructor === String) ||
            (typeof value === 'number' && value.constructor === Number) ||
            (typeof value === 'bigint' && value.constructor === BigInt) ||
            (typeof value === 'boolean' && value.constructor === Boolean) ||
            (value instanceof Uint8Array);

        if (!isCorrectType) {
            throw new TideError({ code: TideJsErrorCodes.MODEL_INVALID_FIELD, displayMessage: `PolicyParameters.getParameter: parameter '${key}' exists but has unexpected type '${actualType}'`, source: "tide-js/Models/Policy.ts:219" });
        }

        return value as T;
    }

    toBytes(): Uint8Array {
        let params = [];

        for (const [key, value] of this.entries) {
            const nameBytes = StringToUint8Array(key);
            let dataBytes, typeStr;

            if (typeof value === 'string') {
                dataBytes = StringToUint8Array(value);
                typeStr = "str";
            } else if (typeof value === 'number' && Number.isInteger(value)) {
                const buffer = new ArrayBuffer(4);
                const view = new DataView(buffer);
                view.setInt32(0, value, true); // little-endian
                dataBytes = new Uint8Array(buffer);
                typeStr = "num";
            } else if (typeof value === 'bigint') {
                dataBytes = BigIntToByteArray(value);
                typeStr = "bnum";
            } else if (typeof value === 'boolean') {
                dataBytes = new Uint8Array([value ? 1 : 0]);
                typeStr = "bln";
            } else if (value instanceof Uint8Array) {
                dataBytes = value;
                typeStr = "byt";
            } else {
                throw new TideError({ code: TideJsErrorCodes.MODEL_UNKNOWN_PARAM_TYPE, displayMessage: `PolicyParameters.toBytes: could not serialize key '${key}' of type '${typeof value}'`, source: "tide-js/Models/Policy.ts:253" });
            }

            const typeBytes = StringToUint8Array(typeStr);
            const paramMemory = TideMemory.CreateFromArray([nameBytes, typeBytes, dataBytes]);
            params.push(paramMemory);
        }

        return TideMemory.CreateFromArray(params);
    }
}

class PolicyV2 extends Policy{
    static thisVersion = "2";
    static from(data: TideMemory): Policy {
        const dataToVerify = data.GetValue(0);
        const v = StringFromUint8Array(dataToVerify.GetValue(0));
        if (v != PolicyV2.thisVersion) {
            throw new TideError({ code: TideJsErrorCodes.MODEL_DEV_ERROR, displayMessage: `PolicyV2.from: version mismatch (expected ${PolicyV2.thisVersion}, got ${v})`, source: "tide-js/Models/Policy.ts:273" });
        }

        const contractId = StringFromUint8Array(dataToVerify.GetValue(1));
        const modelId = StringFromUint8Array(dataToVerify.GetValue(2));
        const keyId = StringFromUint8Array(dataToVerify.GetValue(3));
        const approvalType: ApprovalType = ApprovalType[StringFromUint8Array(dataToVerify.GetValue(4)) as keyof typeof ApprovalType];
        const executionType: ExecutionType = ExecutionType[StringFromUint8Array(dataToVerify.GetValue(5)) as keyof typeof ExecutionType];

        const params = new PolicyParameters(dataToVerify.GetValue(6));

        const p = new PolicyV2({
            version: v,
            contractId,
            modelId,
            keyId,
            approvalType: approvalType,
            executionType: executionType,
            params
        });

        const sigRes = { result: undefined };
        if (data.TryGetValue(1, sigRes)) {
            p.signature = sigRes.result;
        }

        return p;
    }
    toBytes() {
        let d: Uint8Array[] = [
            TideMemory.CreateFromArray([
                StringToUint8Array(this.version),
                StringToUint8Array(this.contractId),
                StringToUint8Array(this.modelIds[0]),
                StringToUint8Array(this.keyId),
                StringToUint8Array(ApprovalType[this.approvalType]),
                StringToUint8Array(ExecutionType[this.executionType]),
                this.params.toBytes()
            ])];

        if (this.signature) d.push(this.signature);

        return TideMemory.CreateFromArray(d);
    }
}

class PolicyV1 extends Policy {
    static thisVersion = "1";
    static from(data: TideMemory): Policy {
        const dataToVerify = data.GetValue(0);
        const v = StringFromUint8Array(dataToVerify.GetValue(0));
        if (v != PolicyV1.thisVersion) {
            throw new TideError({ code: TideJsErrorCodes.MODEL_DEV_ERROR, displayMessage: `PolicyV1.from: version mismatch (expected ${PolicyV1.thisVersion}, got ${v})`, source: "tide-js/Models/Policy.ts:325" });
        }

        const contractId = StringFromUint8Array(dataToVerify.GetValue(1));
        const modelId = StringFromUint8Array(dataToVerify.GetValue(2));
        const keyId = StringFromUint8Array(dataToVerify.GetValue(3));

        const params = new PolicyParameters(dataToVerify.GetValue(4));

        const p = new PolicyV1({
            version: v,
            contractId,
            modelId,
            keyId,
            approvalType: ApprovalType.EXPLICIT, // didn't exist on v1 so this is default
            executionType: ExecutionType.PUBLIC, // didn't exist on v1 so this is default
            params
        });

        const sigRes = { result: undefined };
        if (data.TryGetValue(1, sigRes)) {
            p.signature = sigRes.result;
        }

        return p;
    }
    toBytes() {
        let d: Uint8Array[] = [
            TideMemory.CreateFromArray([
                StringToUint8Array(PolicyV1.thisVersion),
                StringToUint8Array(this.contractId),
                StringToUint8Array(this.modelIds[0]),
                StringToUint8Array(this.keyId),
                this.params.toBytes()
            ])];

        if (this.signature) d.push(this.signature);

        return TideMemory.CreateFromArray(d);
    }
}