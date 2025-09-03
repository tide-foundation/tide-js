/* ========================= core numeric helpers ========================= */

function isIntegerString(s) {
  return typeof s === "string" && /^-?\d+$/.test(s.trim());
}

function toBigIntStrict(x) {
  if (typeof x === "bigint") return x;
  if (typeof x === "number") {
    if (!Number.isFinite(x) || !Number.isInteger(x)) throw new TypeError("Non-integer number");
    return BigInt(x);
  }
  if (isIntegerString(x)) return BigInt(x.trim());
  throw new TypeError("Unsupported type for BigInt");
}

function toComparableBigInt(value) {
  // arrays compare by length (matches C# IsLess/Greater for arrays)
  if (Array.isArray(value)) return BigInt(value.length);
  return toBigIntStrict(value);
}

/* ========================= Hedera helpers ========================= */

function convertHederaValue(low, high, unsigned) {
  const lo = BigInt.asUintN(32, BigInt(low));
  const hi = BigInt.asUintN(32, BigInt(high));
  const combined = (hi << 32n) | lo;
  return unsigned ? combined : BigInt.asIntN(64, combined);
}

function tryReadHederaBigInt(obj) {
  if (!obj || typeof obj !== "object") return { ok: false };
  if (!("low" in obj) || !("high" in obj) || !("unsigned" in obj)) return { ok: false };
  try {
    const n = convertHederaValue(obj.low, obj.high, !!obj.unsigned);
    return { ok: true, n };
  } catch {
    return { ok: false };
  }
}

/* Unifies numeric parsing for Number, BigInt, integer String, and Hedera object */
function tryGetNumericEquivalent(value) {
  try {
    return { ok: true, n: toBigIntStrict(value) };
  } catch {
    // fallthrough
  }
  const hedera = tryReadHederaBigInt(value);
  if (hedera.ok) return hedera;
  return { ok: false };
}

/* ========================= JSON equality ========================= */

export function jsonEquals(a, b) {
  // Handle null/undefined
  if (a == null || b == null) return a === b;

  // 1) Numeric-aware path (number | bigint | integer string | Hedera object)
  const an = tryGetNumericEquivalent(a);
  const bn = tryGetNumericEquivalent(b);
  if (an.ok && bn.ok) return an.n === bn.n;

  // 2) If types differ and not numerically comparable, not equal
  const ta = typeof a, tb = typeof b;
  if (ta !== "object" && tb !== "object") return a === b;

  // 3) Arrays (structural)
  const aArr = Array.isArray(a), bArr = Array.isArray(b);
  if (aArr || bArr) {
    if (!(aArr && bArr)) return false;
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!jsonEquals(a[i], b[i])) return false;
    }
    return true;
  }

  // 4) Objects (structural, after numeric attempt)
  if (ta === "object" && tb === "object") {
    const ak = Object.keys(a).sort();
    const bk = Object.keys(b).sort();
    if (ak.length !== bk.length) return false;
    for (let i = 0; i < ak.length; i++) {
      if (ak[i] !== bk[i]) return false;
      if (!jsonEquals(a[ak[i]], b[bk[i]])) return false;
    }
    return true;
  }

  return false;
}

/* ========================= public evaluators ========================= */

export function isLessThan(value, ruleValue) {
  try {
    const left = toComparableBigInt(value);
    const right = toBigIntStrict(ruleValue);
    return left < right;
  } catch {
    return false;
  }
}

export function isGreaterThan(value, ruleValue) {
  try {
    const left = toComparableBigInt(value);
    const right = toBigIntStrict(ruleValue);
    return left > right;
  } catch {
    return false;
  }
}

export function isEqualTo(value, ruleValue) {
  return jsonEquals(value, ruleValue);
}

/* -------- filters (return true to EXCLUDE the item) -------- */

export function filterValuesEqualTo(value, valueToExclude) {
  return jsonEquals(value, valueToExclude);
}

export function filterValuesNotEqualTo(value, valueToKeep) {
  return !jsonEquals(value, valueToKeep);
}

/* -------- totals (numbers) -------- */

export function isTotalLessThan(elements, ruleValue) {
  try {
    const threshold = toBigIntStrict(ruleValue);
    let total = 0n;
    for (const el of elements) total += toBigIntStrict(el);
    return total < threshold;
  } catch {
    return false;
  }
}

export function isTotalMoreThan(elements, ruleValue) {
  try {
    const threshold = toBigIntStrict(ruleValue);
    let total = 0n;
    for (const el of elements) total += toBigIntStrict(el);
    return total > threshold;
  } catch {
    return false;
  }
}

/* ========================= Hedera ========================= */

// Per-element: value is the Hedera object {low, high, unsigned}
export function isHederaLessThan(value, threshold) {
  const hv = tryReadHederaBigInt(value);
  if (!hv.ok) return false;
  const thr = toBigIntStrict(threshold);
  return hv.n < thr;
}

export function isHederaGreaterThan(value, threshold) {
  const hv = tryReadHederaBigInt(value);
  if (!hv.ok) return false;
  const thr = toBigIntStrict(threshold);
  return hv.n > thr;
}

// Aggregates: elements is an array of {low, high, unsigned}
export function isHederaTotalLessThan(elements, threshold) {
  const thr = toBigIntStrict(threshold);
  let total = 0n;
  for (const el of elements) {
    const hv = tryReadHederaBigInt(el);
    if (!hv.ok) return false;
    total += hv.n;
  }
  return total < thr;
}

export function isHederaTotalMoreThan(elements, threshold) {
  const thr = toBigIntStrict(threshold);
  let total = 0n;
  for (const el of elements) {
    const hv = tryReadHederaBigInt(el);
    if (!hv.ok) return false;
    total += hv.n;
  }
  return total > thr;
}

/* ========================= Back-compat aliases (optional) ========================= */
// Old names kept for compatibility; prefer the new names above.
export const isHederaTransactionLessThan = isHederaLessThan;
export const isHederaTransactionMoreThan  = isHederaGreaterThan;
