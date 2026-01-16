import { TideMemory } from "../Tools/TideMemory";
import { BigIntToByteArray, BigIntFromByteArray, StringFromUint8Array, StringToUint8Array } from "../Cryptide/Serialization";

export enum ApprovalType {
    EXPLICIT,
    IMPLICIT
}
export enum ExecutionType {
    PRIVATE,
    PUBLIC
}
export class Policy {
    static latestVersion: string = "2";
    version: string;
    contractId: string;
    modelId: string;
    keyId: string;
    approvalType: ApprovalType;
    executionType: ExecutionType;
    params: PolicyParameters;

    dataToVerify: TideMemory | undefined;
    signature: Uint8Array | undefined;

    constructor(data: { version: string, contractId: string, modelId: string, keyId: string, approvalType: ApprovalType, executionType: ExecutionType, params: Map<string, any> | PolicyParameters }) {
        if (typeof data["version"] !== "string") throw 'Version is not a string';
        this.version = data["version"];
        if (typeof data["contractId"] !== "string") throw 'ContractId is not a string';
        this.contractId = data["contractId"];
        if (typeof data["modelId"] !== "string") throw 'ModelId is not a string';
        this.modelId = data["modelId"];
        if (typeof data["keyId"] !== "string") throw 'KeyId is not a string';
        this.keyId = data["keyId"];

        this.approvalType = data.approvalType;
        this.executionType = data.executionType;

        if (!data["params"]) throw 'Params is null';
        this.params = data["params"] instanceof PolicyParameters ? data["params"] : new PolicyParameters(data["params"]);

        this.dataToVerify = TideMemory.CreateFromArray([
            StringToUint8Array(this.version),
            StringToUint8Array(this.contractId),
            StringToUint8Array(this.modelId),
            StringToUint8Array(this.keyId),
            StringToUint8Array(ApprovalType[this.approvalType]),
            StringToUint8Array(ExecutionType[this.executionType]),
            this.params.toBytes()]);
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
                default:
                    throw Error("Unknown policy version: " + version);
            }
        }

        const contractId = StringFromUint8Array(dataToVerify.GetValue(1));
        const modelId = StringFromUint8Array(dataToVerify.GetValue(2));
        const keyId = StringFromUint8Array(dataToVerify.GetValue(3));
        const approvalType: ApprovalType = ApprovalType[StringFromUint8Array(dataToVerify.GetValue(4)) as keyof typeof ApprovalType];
        const executionType: ExecutionType = ExecutionType[StringFromUint8Array(dataToVerify.GetValue(5)) as keyof typeof ExecutionType];

        const params = new PolicyParameters(dataToVerify.GetValue(6));

        const p = new Policy({
            version,
            contractId,
            modelId,
            keyId,
            approvalType,
            executionType,
            params
        });

        const sigRes = { result: undefined };
        if (d.TryGetValue(1, sigRes)) {
            p.signature = sigRes.result;
        }
        return p;
    }

    toBytes() {
        let d: Uint8Array[] = [
            TideMemory.CreateFromArray([
                StringToUint8Array(this.version),
                StringToUint8Array(this.contractId),
                StringToUint8Array(this.modelId),
                StringToUint8Array(this.keyId),
                StringToUint8Array(ApprovalType[this.approvalType]),
                StringToUint8Array(ExecutionType[this.executionType]),
                this.params.toBytes()
            ])];

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
                    throw new Error(`Could not find type of ${type}`);
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
            throw new Error(`Parameter '${key}' not found`);
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
            throw new Error(
                `Parameter '${key}' exists but has unexpected type '${actualType}'`
            );
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
                throw new Error(
                    `Could not serialize key '${key}' of type '${typeof value}'`
                );
            }

            const typeBytes = StringToUint8Array(typeStr);
            const paramMemory = TideMemory.CreateFromArray([nameBytes, typeBytes, dataBytes]);
            params.push(paramMemory);
        }

        return TideMemory.CreateFromArray(params);
    }
}

class PolicyV1 extends Policy {
    static thisVersion = "1";
    version: string = PolicyV1.thisVersion;
    static from(data: TideMemory): Policy {
        const dataToVerify = data.GetValue(0);
        const v = StringFromUint8Array(dataToVerify.GetValue(0));
        if (v != PolicyV1.thisVersion) {
            throw Error("Dev error");
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
                StringToUint8Array(this.modelId),
                StringToUint8Array(this.keyId),
                this.params.toBytes()
            ])];

        if (this.signature) d.push(this.signature);

        return TideMemory.CreateFromArray(d);
    }
}