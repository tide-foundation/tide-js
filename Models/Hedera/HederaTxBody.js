export default class HederaTxBody {
  constructor(bytes) {
    if (!bytes || !bytes.length) throw new Error("TransactionBody bytes are empty");
    const bodyBytes = unwrapHederaBody(bytes); // robust unwrap
    this.transaction = HederaTransaction.deserialize(bodyBytes);
  }
  toPrettyObject() {
    return buildOriginalJSONFromParsed(this.transaction);
  }
  // Optional alias if you prefer a more explicit name:
  toOriginalObject() {
    return buildOriginalJSONFromParsed(this.transaction);
  }
}

/* -------------------------------- Core model -------------------------------- */

class HederaTransaction {
  constructor({
    transactionId = null,
    nodeAccountId = null,
    transactionFee = 0n,
    transactionValidDuration = null,
    memo = "",
    cryptoTransfer = null,
  } = {}) {
    this.transactionId = transactionId;                       // TransactionId
    this.nodeAccountId = nodeAccountId;                       // AccountId
    this.transactionFee = BigInt(transactionFee);             // u64 tinybar
    this.transactionValidDuration = transactionValidDuration; // Duration { seconds }
    this.memo = memo;                                         // string
    this.cryptoTransfer = cryptoTransfer;                     // CryptoTransferTransactionBody (subset)
  }

  static deserialize(bytes) {
    const r = new ProtoReader(bytes);
    return HederaTransaction.parseTransactionBody(r);
  }

  static parseTransactionBody(r) {
    const tx = new HederaTransaction();
    while (!r.eof()) {
      const { field, wire } = r.tag();
      switch (field) {
        case 1: // transaction_id (TransactionId)
          tx.transactionId = parseTransactionId(new ProtoReader(r.bytes()));
          break;
        case 2: // node_account_id (AccountId)
          tx.nodeAccountId = parseAccountId(new ProtoReader(r.bytes()));
          break;
        case 3: // transaction_fee (uint64)
          tx.transactionFee = r.varint(); // BigInt (unsigned)
          break;
        case 4: // transaction_valid_duration (Duration)
          tx.transactionValidDuration = parseDuration(new ProtoReader(r.bytes()));
          break;
        case 5: // generate_record (bool) [deprecated]
          r.varint(); // ignore
          break;
        case 6: // memo (string)
          tx.memo = r.string();
          break;
        case 73: // batch_key (Key) -> skip
          r.skip(wire);
          break;
        case 1001: // max_custom_fees (repeated CustomFeeLimit) -> skip here
          r.skip(wire);
          break;

        // --- oneof data (we only parse CryptoTransfer) ---
        case 14: // cryptoTransfer (CryptoTransferTransactionBody)
          tx.cryptoTransfer = parseCryptoTransfer(new ProtoReader(r.bytes()));
          break;

        default:
          r.skip(wire);
      }
    }
    return tx;
  }
}

/* ------------------------- Parsers for nested messages ------------------------- */

function parseTransactionId(r) {
  const out = { transactionValidStart: null, accountId: null, scheduled: false, nonce: 0 };
  while (!r.eof()) {
    const { field, wire } = r.tag();
    switch (field) {
      case 1: // Timestamp
        out.transactionValidStart = parseTimestamp(new ProtoReader(r.bytes()));
        break;
      case 2: // AccountId
        out.accountId = parseAccountId(new ProtoReader(r.bytes()));
        break;
      case 3: // bool scheduled
        out.scheduled = r.varint() !== 0n;
        break;
      case 4: // int32 nonce
        out.nonce = Number(r.varint()); // i32
        break;
      default:
        r.skip(wire);
    }
  }
  return out;
}

function parseTimestamp(r) {
  const out = { seconds: 0n, nanos: 0 };
  while (!r.eof()) {
    const { field, wire } = r.tag();
    switch (field) {
      case 1: // int64 seconds
        out.seconds = r.varintSigned();
        break;
      case 2: // int32 nanos
        out.nanos = Number(r.varint());
        break;
      default:
        r.skip(wire);
    }
  }
  return out;
}

function parseDuration(r) {
  const out = { seconds: 0n };
  while (!r.eof()) {
    const { field, wire } = r.tag();
    if (field === 1) out.seconds = r.varintSigned(); // int64
    else r.skip(wire);
  }
  return out;
}

function parseAccountId(r) {
  const out = { shard: 0n, realm: 0n, account: null, aliasHex: null };
  while (!r.eof()) {
    const { field, wire } = r.tag();
    switch (field) {
      case 1: // shard_num int64
        out.shard = r.varintSigned();
        break;
      case 2: // realm_num int64
        out.realm = r.varintSigned();
        break;
      case 3: // accountNum (oneof account)
        out.account = r.varintSigned();
        break;
      case 4: // alias bytes (oneof account)
        out.aliasHex = bytesToHex(r.bytes());
        break;
      default:
        r.skip(wire);
    }
  }
  return out;
}

function parseAccountAmount(r) {
  const out = { accountId: null, amount: 0n, isApproval: false };
  while (!r.eof()) {
    const { field, wire } = r.tag();
    switch (field) {
      case 1: // AccountId
        out.accountId = parseAccountId(new ProtoReader(r.bytes()));
        break;
      case 2: // sint64 amount (zigzag)
        out.amount = r.sint64();
        break;
      case 3: // bool is_approval
        out.isApproval = r.varint() !== 0n;
        break;
      default:
        r.skip(wire);
    }
  }
  return out;
}

function parseTransferList(r) {
  const out = { accountAmounts: [] };
  while (!r.eof()) {
    const { field, wire } = r.tag();
    if (field === 1) {
      out.accountAmounts.push(parseAccountAmount(new ProtoReader(r.bytes())));
    } else {
      r.skip(wire);
    }
  }
  return out;
}

function parseCryptoTransfer(r) {
  const out = { transfers: null /* HBAR list */ /* , tokenTransfers: ignored */ };
  while (!r.eof()) {
    const { field, wire } = r.tag();
    switch (field) {
      case 1: // TransferList (HBAR)
        out.transfers = parseTransferList(new ProtoReader(r.bytes()));
        break;
      case 2: // repeated TokenTransferList (complex) -> skip
        r.skip(wire);
        break;
      default:
        r.skip(wire);
    }
  }
  return out;
}

/* ------------------------------ Minimal protobuf ------------------------------ */

export class ProtoReader {
  constructor(bytes) {
    this.u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    this.i = 0;
    this.len = this.u8.length;
    this._td = (typeof TextDecoder !== "undefined") ? new TextDecoder() : null;
  }
  eof() { return this.i >= this.len; }
  varint() {
    let out = 0n, shift = 0n;
    for (;;) {
      if (this.i >= this.len) throw new Error("truncated varint");
      const b = this.u8[this.i++];
      out |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7n;
      if (shift > 70n) throw new Error("varint too long");
    }
    return out;
  }
  // two's-complement signed int64 (for protobuf int64)
  varintSigned() {
    const u = this.varint();
    const mask64 = (1n << 64n) - 1n;
    const v = u & mask64;
    return (v & (1n << 63n)) ? (v - (1n << 64n)) : v;
  }
  // zigzag (for protobuf sint64)
  sint64() {
    const u = this.varint();
    return (u >> 1n) ^ (-(u & 1n));
  }
  tag() {
    const key = this.varint();
    return { field: Number(key >> 3n), wire: Number(key & 7n) };
  }
  bytes() {
    const n = Number(this.varint());
    if (this.i + n > this.len) throw new Error("truncated bytes");
    const b = this.u8.subarray(this.i, this.i + n);
    this.i += n;
    return b;
  }
  string() {
    const b = this.bytes();
    if (this._td) return this._td.decode(b);
    let s = "", i = 0; while (i < b.length) s += String.fromCharCode(b[i++]);
    return decodeURIComponent(escape(s));
  }
  skip(wire) {
    switch (wire) {
      case 0: this.varint(); return;
      case 1: this.i += 8; return;
      case 2: this.i += Number(this.varint()); return;
      case 5: this.i += 4; return;
      default: throw new Error("unsupported wire type " + wire);
    }
  }
}

/* ---------- Unwrap helpers: Transaction / SignedTransaction → TransactionBody ---------- */

export function stripLengthPrefixIfPresent(u8) {
  let i = 0, shift = 0, len = 0;
  for (;;) {
    if (i >= u8.length || shift > 28) return u8;
    const b = u8[i++];
    len |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
  }
  return (u8.length - i === len) ? u8.subarray(i, i + len) : u8;
}

export function looksLikeTransactionBody(u8) {
  try {
    const r = new ProtoReader(u8);
    const t = r.tag();
    if (t.field !== 1 || t.wire !== 2) return false; // expect TransactionId at field 1 (LD)
    const inner = new ProtoReader(r.bytes());
    const t2 = inner.tag(); // Timestamp(1) or AccountId(2)
    return t2.wire === 2 && (t2.field === 1 || t2.field === 2);
  } catch { return false; }
}

export function tryExtractBodyFromTransaction(u8) {
  const r = new ProtoReader(u8);
  let signed = null, body = null;
  while (!r.eof()) {
    const { field, wire } = r.tag();
    if (wire !== 2) { r.skip(wire); continue; }
    const val = r.bytes();
    if (field === 1) signed = val;     // Transaction.signedTransactionBytes
    else if (field === 2) body = val;  // Transaction.bodyBytes (deprecated)
  }
  if (body) return body;
  if (signed) return tryExtractBodyFromSigned(signed);
  return null;
}

export function tryExtractBodyFromSigned(u8) {
  const r = new ProtoReader(u8);
  let bodyBytes = null, bodyMsg = null;
  while (!r.eof()) {
    const { field, wire } = r.tag();
    if (wire !== 2) { r.skip(wire); continue; }
    const val = r.bytes();
    if (field === 1) bodyBytes = val;   // old: bodyBytes
    else if (field === 4) bodyMsg = val; // new: body (embedded TransactionBody)
  }
  return bodyBytes || bodyMsg;
}

export function unwrapHederaBody(u8) {
  if (!(u8 instanceof Uint8Array)) u8 = new Uint8Array(u8);
  if (looksLikeTransactionBody(u8)) return u8;
  const fromTx = tryExtractBodyFromTransaction(u8);
  if (fromTx) return fromTx;
  const fromSigned = tryExtractBodyFromSigned(u8);
  if (fromSigned) return fromSigned;
  const stripped = stripLengthPrefixIfPresent(u8);
  if (stripped !== u8) return unwrapHederaBody(stripped);
  return u8;
}

/* ----------------------------- Build ORIGINAL JSON ---------------------------- */

function bytesToHex(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += (u8[i] >>> 4).toString(16) + (u8[i] & 0xF).toString(16);
  return s;
}
function hexToU8(hex) {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const u8 = new Uint8Array(h.length / 2);
  for (let i = 0; i < u8.length; i++) u8[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return u8;
}
function bufferLike(u8) {
  return { type: "Buffer", data: Array.from(u8) };
}
const MASK_32 = 0xFFFFFFFFn;
function toInt32(n) { return Number(BigInt.asIntN(32, n)); }
function toUint32(n) { return Number(BigInt.asUintN(32, n)); }
function splitInt64Signed(x) {
  // two's complement signed 64 → signed 32-bit parts
  const u = BigInt.asUintN(64, x);
  const lo = u & MASK_32;
  const hi = u >> 32n;
  return { low: toInt32(lo), high: toInt32(hi), unsigned: false };
}
function splitUint64(x) {
  const u = BigInt.asUintN(64, x);
  const lo = u & MASK_32;
  const hi = u >> 32n;
  return { low: toUint32(lo), high: toUint32(hi), unsigned: true };
}

function accountIdOriginal(a) {
  if (!a) return null;
  const base = {
    shardNum: splitInt64Signed(a.shard ?? 0n),
    realmNum: splitInt64Signed(a.realm ?? 0n),
  };
  if (a.account != null) {
    return { ...base, accountNum: splitInt64Signed(a.account) };
  }
  if (a.aliasHex) {
    return { ...base, alias: bufferLike(hexToU8(a.aliasHex)) };
  }
  return base;
}

function buildOriginalJSONFromParsed(tx) {
  const obj = {
    maxCustomFees: [], // not parsed in this lightweight reader
    transactionID: {
      transactionValidStart: {
        seconds: splitInt64Signed(tx.transactionId?.transactionValidStart?.seconds ?? 0n),
        nanos: tx.transactionId?.transactionValidStart?.nanos ?? 0,
      },
      accountID: accountIdOriginal(tx.transactionId?.accountId),
      scheduled: !!tx.transactionId?.scheduled,
      // nonce is optional; include only if non-zero to match your sample (omitted there)
      // nonce: tx.transactionId?.nonce ?? 0
    },
    nodeAccountID: accountIdOriginal(tx.nodeAccountId),
    transactionFee: splitUint64(tx.transactionFee ?? 0n),
    transactionValidDuration: {
      seconds: splitInt64Signed(tx.transactionValidDuration?.seconds ?? 120n),
    },
    memo: tx.memo ?? "",
    cryptoTransfer: {
      tokenTransfers: [], // not parsed here
      transfers: {
        accountAmounts: [],
      },
    },
  };

  const accountAmounts = tx.cryptoTransfer?.transfers?.accountAmounts || [];
  for (const aa of accountAmounts) {
    const amt = (typeof aa.amount === "bigint") ? aa.amount : BigInt(aa.amount ?? 0);
    obj.cryptoTransfer.transfers.accountAmounts.push({
      accountID: accountIdOriginal(aa.accountId),
      amount: splitInt64Signed(amt), // sint64 → signed parts
      isApproval: !!aa.isApproval,
    });
  }

  return obj;
}

/* ----------------------------- Optional: JSON replacer ----------------------------- */
function bigIntReplacer(_k, v) { return typeof v === 'bigint' ? v.toString() : v; }
