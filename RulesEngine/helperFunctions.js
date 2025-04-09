// helperFunctions.js (ESM)
export function isLessThan(value, ruleValue) {
    const threshold = BigInt(ruleValue);
    if (Array.isArray(value)) {
      return BigInt(value.length) < threshold;
    }
    try {
      return BigInt(value) < threshold;
    } catch (e) {
      return false;
    }
  }
  
  export function isGreaterThan(value, ruleValue) {
    const threshold = BigInt(ruleValue);
    if (Array.isArray(value)) {
      return BigInt(value.length) > threshold;
    }
    try {
      return BigInt(value) > threshold;
    } catch (e) {
      return false;
    }
  }
  
  export function isEqualTo(value, ruleValue) {
    if (typeof value === "number" || typeof value === "bigint") {
      try {
        return BigInt(value) === BigInt(ruleValue);
      } catch (e) {
        return false;
      }
    }
    return String(value) === ruleValue;
  }
  
  export function filterValuesEqualTo(value, valueToExclude) {
    return String(value) === valueToExclude;
  }
  
  export function filterValuesNotEqualTo(value, valueToKeep) {
    return String(value) !== valueToKeep;
  }
  
  export function isTotalLessThan(elements, ruleValue) {
    const threshold = BigInt(ruleValue);
    let total = BigInt(0);
    for (const el of elements) {
      try {
        total += BigInt(el);
      } catch (e) {
        return false;
      }
    }
    return total < threshold;
  }
  
  export function isTotalMoreThan(elements, ruleValue) {
    const threshold = BigInt(ruleValue);
    let total = BigInt(0);
    for (const el of elements) {
      try {
        total += BigInt(el);
      } catch (e) {
        return false;
      }
    }
    return total > threshold;
  }
  