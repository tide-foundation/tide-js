import { Bytes2Hex } from "../../Cryptide/Serialization.js"  

export default class CardanoTxBody {
    constructor(data){
        this.transaction = CardanoTransaction.deserializeTransaction(data);
    }

    toPrettyObject(){
        const serializeBigInts = JSON.stringify(this.transaction, bigIntReplacer, 2)
        return JSON.parse(serializeBigInts);
    }
}

class CardanoTransaction {
    // Represents a full transaction (inputs, outputs, fee, and optional TTL)
    constructor(inputs, outputs, fee, ttl = null) {
      if (!inputs) throw new Error("inputs is required");
      if (!outputs) throw new Error("outputs is required");
      this.inputs = inputs;            // Array of CardanoTransactionInput
      this.outputs = outputs;          // Array of CardanoTransactionOutput
      this.fee = BigInt(fee);          // Fee as BigInt
      this.ttl = ttl !== null ? BigInt(ttl) : null; // TTL as BigInt (if provided)
    }
  
    // Calculates the total amount from the provided UTXOs for the inputs
    totalInputAmount(utxos) {
      const utxoLookup = new Map();
      for (const u of utxos) {
        // Create a composite key (txHash|txIndex)
        utxoLookup.set(`${u.txHash}|${u.txIndex}`, BigInt(u.amount));
      }
      let total = 0n;
      for (const input of this.inputs) {
        const key = `${input.txHash}|${input.txIndex}`;
        if (utxoLookup.has(key)) {
          total += utxoLookup.get(key);
        }
      }
      return total;
    }
  
    // Deserialize a CBOR byte array into a CardanoTransaction object
    static deserializeTransaction(cborBytes) {
      if (!cborBytes || cborBytes.length === 0) {
        throw new Error("CBOR data is empty");
      }
      return CardanoTransaction.parseTransaction(cborBytes);
    }
  
    // Parses CBOR data into a structured CardanoTransaction.
    // This implementation uses a context object to track the current index.
    static parseTransaction(data) {
      const ctx = { data: data, index: 0 };
  
      if (ctx.data.length === 0) {
        throw new Error("Transaction data is empty");
      }
      // Expect the map header (0xA4 indicates a map with 4 key-value pairs)
      if (ctx.data[ctx.index++] !== 0xA4) {
        throw new Error("Invalid CBOR transaction format, expected map (A4)");
      }
  
      // --- Helper functions operating on ctx ---
      function readArrayLength(ctx) {
        let firstByte = ctx.data[ctx.index++];
        if ((firstByte & 0xE0) === 0x80) { // Array type
          let length = firstByte & 0x1F;
          if (length === 24) length = ctx.data[ctx.index++];
          if (length === 25) length = (ctx.data[ctx.index++] << 8) | ctx.data[ctx.index++];
          return length;
        } else if (firstByte === 0x9F) { // Indefinite-length array
          return -1;
        }
        throw new Error(`Expected CBOR array format, but found ${firstByte.toString(16)} at index ${ctx.index}`);
      }
  
      function readArrayStart(ctx) {
        if ((ctx.data[ctx.index] & 0xE0) !== 0x80) {
          throw new Error("Expected CBOR nested array format");
        }
        ctx.index++;
      }
  
      function readByteString(ctx) {
        if ((ctx.data[ctx.index] & 0xE0) !== 0x40) {
          throw new Error("Invalid CBOR byte string format");
        }
        let length = ctx.data[ctx.index++] & 0x1F;
        if (length === 24) length = ctx.data[ctx.index++];
        if (length === 25) length = (ctx.data[ctx.index++] << 8) | ctx.data[ctx.index++];
        const result = ctx.data.slice(ctx.index, ctx.index + length);
        ctx.index += length;
        return result;
      }
  
      function readUnsignedInt(ctx) {
        let type = ctx.data[ctx.index++];
        if (type <= 0x17) {
          return BigInt(type);
        } else if (type === 0x18) {
          return BigInt(ctx.data[ctx.index++]);
        } else if (type === 0x19) {
          const val = (ctx.data[ctx.index] << 8) | ctx.data[ctx.index + 1];
          ctx.index += 2;
          return BigInt(val);
        } else if (type === 0x1A) {
          const bytes = ctx.data.slice(ctx.index, ctx.index + 4);
          ctx.index += 4;
          let val = 0;
          for (const b of bytes) {
            val = (val << 8) | b;
          }
          return BigInt(val);
        } else if (type === 0x1B) {
          const bytes = ctx.data.slice(ctx.index, ctx.index + 8);
          ctx.index += 8;
          let val = 0n;
          for (const b of bytes) {
            val = (val << 8n) | BigInt(b);
          }
          return val;
        } else {
          throw new Error(`Unexpected CBOR integer type: ${type}`);
        }
      }
      // --- End helper functions ---
  
      // Process Inputs
      if (ctx.data[ctx.index++] !== 0) {
        throw new Error("Expected inputs key (0)");
      }
      if (
        ctx.data[ctx.index++] !== 0xD9 ||
        ctx.data[ctx.index++] !== 0x01 ||
        ctx.data[ctx.index++] !== 0x02
      ) {
        throw new Error("Expected tagged UTXO format (D9 01 02)");
      }
      const inputArrayLength = readArrayLength(ctx);
      const inputs = [];
      for (let i = 0; i < inputArrayLength; i++) {
        readArrayStart(ctx);
        const txHashBytes = readByteString(ctx);
        const txIndex = Number(readUnsignedInt(ctx));
        const txHash = Bytes2Hex(txHashBytes);
        inputs.push(new CardanoTransactionInput(txHash, txIndex));
      }
  
      // Process Outputs
      if (ctx.data[ctx.index++] !== 1) {
        throw new Error("Expected outputs key (1)");
      }
      const outputArrayLength = readArrayLength(ctx);
      const outputs = [];
      for (let i = 0; i < outputArrayLength; i++) {
        readArrayStart(ctx);
        const addressBytes = readByteString(ctx);
        const amount = readUnsignedInt(ctx);
        const address = Bytes2Hex(addressBytes);
        outputs.push(new CardanoTransactionOutput(address, amount));
      }
  
      // Process Fee
      if (ctx.data[ctx.index++] !== 2) {
        throw new Error("Expected fee key (2)");
      }
      const fee = readUnsignedInt(ctx);
      if (fee < 0) {
        throw new Error("Invalid transaction fee: " + fee);
      }
  
      // Process TTL
      if (ctx.data[ctx.index++] !== 3) {
        throw new Error("Expected TTL key (3)");
      }
      const ttl = readUnsignedInt(ctx);
      if (ttl < 0) {
        throw new Error("Invalid transaction TTL: " + ttl);
      }
  
      return new CardanoTransaction(inputs, outputs, fee, ttl);
    }
  }
  
  class CardanoTransactionInput {
    // Represents an input in a Cardano transaction
    constructor(txHash, txIndex) {
      this.txHash = txHash;             // Transaction ID (hex string)
      this.txIndex = txIndex;           // Output index (number)
    }
  }
  
  class CardanoTransactionOutput {
    // Represents an output in a Cardano transaction
    constructor(address, amount) {
      this.address = address;           // Destination address (hex string)
      this.amount = BigInt(amount);     // Amount in Lovelace as BigInt
    }
  }
  

  function bigIntReplacer(key, value) {
    return typeof value === 'bigint' ? value.toString() : value;
  }
