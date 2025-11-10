import { Serialization } from "../Cryptide";
import { BigIntFromByteArray, StringFromUint8Array, StringToUint8Array } from "../Cryptide/Serialization";

export default class Policy{
    constructor(data){
        if(data){
            this.version = StringFromUint8Array(Serialization.GetValue(data, 0));
            this.contractId = StringFromUint8Array(Serialization.GetValue(data, 1));
            this.modelId = StringFromUint8Array(Serialization.GetValue(data, 2));
            this.keyId = StringFromUint8Array(Serialization.GetValue(data, 3));
            this.params = new PolicyParameters(Serialization.GetValue(data, 4));
        }
    }
}

class PolicyParameters {
    /**
     * @param {Map<string, any> | Uint8Array} data - Either a Map of parameters or encoded bytes
     */
    constructor(data) {
        this.params = new Map();
        
        if (data instanceof Map) {
            // Copy from existing Map
            this.params = new Map(data);
        } else if (data instanceof Uint8Array) {
            // Decode from bytes
            this._decodeFromBytes(data);
        } else if (typeof data === 'object' && data !== null) {
            // Convert plain object to Map
            for (const [key, value] of Object.entries(data)) {
                this.params.set(key, value);
            }
        }
    }

    /**
     * Decode parameters from bytes
     * @param {Uint8Array} data 
     */
    _decodeFromBytes(data) {
        let i = 0;
        let value;
        
        // Try to get values at sequential indices
        while (Serialization.TryGetValue(data, i, value)) {
            const nameBytes = Serialization.GetValue(value, 0);
            const name = bytesToString(nameBytes);
            
            const typeBytes = Serialization.GetValue(value, 1);
            const type = bytesToString(typeBytes);
            
            const dataBytes = Serialization.GetValue(value, 2);
            
            let datum;
            switch (type) {
                case "str":
                    datum = bytesToString(dataBytes);
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
            
            this.params.set(name, datum);
            i++;
        }
    }

    /**
     * Convert bytes to BigInt (little-endian)
     * @param {Uint8Array} bytes 
     * @returns {BigInt}
     */
    _bytesToBigInt(bytes) {
        let result = 0n;
        for (let i = bytes.length - 1; i >= 0; i--) {
            result = (result << 8n) | BigInt(bytes[i]);
        }
        return result;
    }

    /**
     * Serialize parameters to bytes
     * @returns {Uint8Array}
     */
    toBytes() {
        let params = [];
        
        for (const [key, value] of this.params) {
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
                dataBytes = this._bigIntToBytes(value);
                typeStr = "bnum";
            } else if (typeof value === 'boolean') {
                dataBytes = new Uint8Array([value ? 1 : 0]);
                typeStr = "bln";
            } else if (value instanceof Uint8Array) {
                dataBytes = value;
                typeStr = "byt";
            } else {
                throw new ParameterUnknownTypeException(
                    `Could not serialize key '${key}' of type '${typeof value}'`
                );
            }
            
            const typeBytes = StringToUint8Array(typeStr);
            const paramMemory = Serialization.CreateTideMemoryFromArray([nameBytes, typeBytes, dataBytes]);
            params.push(paramMemory);
        }
        
        return Serialization.CreateTideMemoryFromArray[params];
    }

    /**
     * Try to get a parameter by key
     * @param {string} key 
     * @param {any} expectedType - Optional type check (constructor function)
     * @returns {{success: boolean, value: any}}
     */
    tryGetParameter(key, expectedType = null) {
        if (this.params.has(key)) {
            const val = this.params.get(key);
            if (expectedType === null || val.constructor === expectedType) {
                return { success: true, value: val };
            }
        }
        return { success: false, value: null };
    }

    /**
     * Get a parameter by key (throws if not found or wrong type)
     * @param {string} key 
     * @param {any} expectedType - Optional type check (constructor function)
     * @returns {any}
     */
    getParameter(key, expectedType = null) {
        if (this.params.has(key)) {
            const val = this.params.get(key);
            if (expectedType !== null && val.constructor !== expectedType) {
                throw new ParameterTypeMismatchException(
                    `You wanted ${expectedType.name} but all we found was a ${val.constructor.name}`
                );
            }
            return val;
        }
        throw new ParameterNotFoundException(`Parameter '${key}' not found`);
    }

    /**
     * Compare two parameter values for equality
     * @param {any} val1 
     * @param {any} val2 
     * @returns {boolean}
     */
    static compare(val1, val2) {
        if (val1 == null || val2 == null) return false;
        
        // Check types match
        if (typeof val1 !== typeof val2) return false;
        if (val1.constructor !== val2.constructor) return false;
        
        if (typeof val1 === 'string' || typeof val1 === 'number' || 
            typeof val1 === 'boolean' || typeof val1 === 'bigint') {
            return val1 === val2;
        }
        
        if (val1 instanceof Uint8Array && val2 instanceof Uint8Array) {
            if (val1.length !== val2.length) return false;
            for (let i = 0; i < val1.length; i++) {
                if (val1[i] !== val2[i]) return false;
            }
            return true;
        }
        
        throw new ParameterUnknownTypeException("Param type not known");
    }

    /**
     * Make the class iterable
     */
    [Symbol.iterator]() {
        return this.params.entries();
    }

    /**
     * Get all entries as an array
     * @returns {Array<[string, any]>}
     */
    entries() {
        return Array.from(this.params.entries());
    }

    /**
     * Get all keys
     * @returns {Array<string>}
     */
    keys() {
        return Array.from(this.params.keys());
    }

    /**
     * Get all values
     * @returns {Array<any>}
     */
    values() {
        return Array.from(this.params.values());
    }
}