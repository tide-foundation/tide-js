// Tide Memory Object helper functions from tide-js
import { TideError } from "../Errors/TideError";
import { TideJsErrorCodes } from "../Errors/codes";

export class TideMemory extends Uint8Array{
    static CreateFromArray(datas: Uint8Array[]): TideMemory   {
        if(datas.length == 0) return new TideMemory();
        const length = datas.reduce((sum, next) => sum + 4 + next.length, 0);
        const mem = this.Create(datas[0], length);
        for(let i = 1; i < datas.length; i++){
            mem.WriteValue(i, datas[i]);
        }
        return mem;
    }
    static Create(initialValue: Uint8Array, totalLength: number, version: number = 1): TideMemory {
        if (totalLength < initialValue.length + 4) {
            throw new TideError({ code: TideJsErrorCodes.MEM_BUFFER_OVERFLOW, displayMessage: `Not enough space to allocate requested data. Make sure to request more space in totalLength than length of InitialValue plus 4 bytes for length. (totalLength=${totalLength}, initialValue.length=${initialValue.length}, required>=${initialValue.length + 4})`, source: "tide-js/Tools/TideMemory.ts:14" });
        }

        // Total buffer length is 4 (version) + totalLength
        const bufferLength = 4 + totalLength;
        const buffer = new TideMemory(bufferLength);
        const dataView = new DataView(buffer.buffer);

        // Write version at position 0 (4 bytes)
        dataView.setInt32(0, version, true); // true for little-endian

        let dataLocationIndex = 4;

        // Write data length of initialValue at position 4 (4 bytes)
        dataView.setInt32(dataLocationIndex, initialValue.length, true);
        dataLocationIndex += 4;

        // Write initialValue starting from position 8
        buffer.set(initialValue, dataLocationIndex);

        return buffer;
    }
    
    WriteValue(index: number, value: Uint8Array): void {
        if (index < 0) throw new TideError({ code: TideJsErrorCodes.MEM_NEGATIVE_INDEX, displayMessage: "Index cannot be less than 0", source: "tide-js/Tools/TideMemory.ts:38" });
        if (index === 0) throw new TideError({ code: TideJsErrorCodes.MEM_INDEX_ZERO_RESERVED, displayMessage: "Use CreateTideMemory to set value at index 0", source: "tide-js/Tools/TideMemory.ts:39" });
        if (this.length < 4 + value.length) throw new TideError({ code: TideJsErrorCodes.MEM_BUFFER_OVERFLOW, displayMessage: `Could not write to memory. Memory too small for this value (this.length=${this.length}, required>=${4 + value.length})`, source: "tide-js/Tools/TideMemory.ts:40" });

        const dataView = new DataView(this.buffer);
        let dataLocationIndex = 4; // Start after the version number

        // Navigate through existing data segments
        for (let i = 0; i < index; i++) {
            if (dataLocationIndex + 4 > this.length) {
                throw new TideError({ code: TideJsErrorCodes.MEM_INDEX_OUT_OF_RANGE, displayMessage: `Index out of range. (while seeking to segment ${index}, sub-index ${i}, offset ${dataLocationIndex}+4 exceeds length ${this.length})`, source: "tide-js/Tools/TideMemory.ts:48" });
            }

            // Read data length at current position
            const nextDataLength = dataView.getInt32(dataLocationIndex, true);
            dataLocationIndex += 4;

            dataLocationIndex += nextDataLength;
        }

        // Check if there's enough space to write the value
        if (dataLocationIndex + 4 + value.length > this.length) {
            throw new TideError({ code: TideJsErrorCodes.MEM_BUFFER_OVERFLOW, displayMessage: `Not enough space to write value (offset ${dataLocationIndex}+4+${value.length} exceeds length ${this.length})`, source: "tide-js/Tools/TideMemory.ts:60" });
        }

        // Check if data has already been written to this index
        const existingLength = dataView.getInt32(dataLocationIndex, true);
        if (existingLength !== 0) {
            throw new TideError({ code: TideJsErrorCodes.MEM_INDEX_ALREADY_WRITTEN, displayMessage: `Data has already been written to this index (index=${index}, offset=${dataLocationIndex}, existingLength=${existingLength})`, source: "tide-js/Tools/TideMemory.ts:66" });
        }

        // Write data length of value at current position
        dataView.setInt32(dataLocationIndex, value.length, true);
        dataLocationIndex += 4;

        // Write value starting from current position
        this.set(value, dataLocationIndex);
    }

    GetValue(index: number): TideMemory{
        // 'a' should be an ArrayBuffer or Uint8Array
        if (this.length < 4) {
            throw new TideError({ code: TideJsErrorCodes.MEM_INSUFFICIENT_DATA, displayMessage: `Insufficient data to read. (buffer length is ${this.length}, need at least 4 bytes for header)`, source: "tide-js/Tools/TideMemory.ts:80" });
        }

        // Create a DataView for reading integers in little-endian format
        const dataView = new DataView(this.buffer, this.byteOffset, this.byteLength);

        // Optional: Read the version if needed
        // const version = dataView.getInt32(0, true);

        let dataLocationIndex = 4;

        for (let i = 0; i < index; i++) {
            // Check if there's enough data to read the length of the next segment
            if (dataLocationIndex + 4 > this.length) {
                throw new TideError({ code: TideJsErrorCodes.MEM_INDEX_OUT_OF_RANGE, displayMessage: `Index out of range. (requested segment ${index}, ran out at sub-index ${i}, offset ${dataLocationIndex}+4 exceeds length ${this.length})`, source: "tide-js/Tools/TideMemory.ts:94" });
            }

            const nextDataLength = dataView.getInt32(dataLocationIndex, true);
            dataLocationIndex += 4 + nextDataLength;
        }

        // Check if there's enough data to read the length of the final segment
        if (dataLocationIndex + 4 > this.length) {
            throw new TideError({ code: TideJsErrorCodes.MEM_INDEX_OUT_OF_RANGE, displayMessage: `Index out of range. (requested segment ${index}, offset ${dataLocationIndex}+4 (length header) exceeds length ${this.length})`, source: "tide-js/Tools/TideMemory.ts:103" });
        }

        const finalDataLength = dataView.getInt32(dataLocationIndex, true);
        dataLocationIndex += 4;

        // Check if the final data segment is within bounds
        if (dataLocationIndex + finalDataLength > this.length) {
            throw new TideError({ code: TideJsErrorCodes.MEM_INDEX_OUT_OF_RANGE, displayMessage: `Index out of range. (requested segment ${index}, payload offset ${dataLocationIndex}+${finalDataLength} exceeds length ${this.length})`, source: "tide-js/Tools/TideMemory.ts:111" });
        }

        return this.subarray(dataLocationIndex, dataLocationIndex + finalDataLength) as TideMemory;
    }

    TryGetValue(index: number, returnObj: {result: Uint8Array | undefined}): boolean{
        try{
            returnObj.result = this.GetValue(index);
            return true;
        }catch{
            returnObj.result = undefined;
            return false;
        }
    }
}