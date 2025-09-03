/** Split "a.b[0].c" -> ["a","b","0","c"]; does NOT handle quoted keys with dots. */
export function splitPath(p) {
  if (Array.isArray(p)) return p.map(String);
  return String(p)
    .replace(/\[(\d+)\]/g, ".$1")
    .split(".")
    .filter(Boolean);
}

/**
 * Recursively retrieves nested values from a JSON object using a dot/bracket field path.
 * Supports objects, arrays, and numeric indices like "a.b[0].c".
 * Returns an array of values or null if the path can't be resolved.
 */
export function tryGetNestedValues(element, fieldPath) {
  const parts = splitPath(fieldPath); // ["a","b","0","c"]
  let current = [element];

  for (const seg of parts) {
    const next = [];
    const isIndex = /^\d+$/.test(seg);
    const index = isIndex ? Number(seg) : null;

    for (const node of current) {
      if (node == null) continue;

      if (isIndex) {
        // When the segment is a numeric index, only arrays can satisfy it
        if (Array.isArray(node) && index >= 0 && index < node.length) {
          next.push(node[index]);
        }
      } else {
        // Property segment
        if (Array.isArray(node)) {
          // Collect the property from each object item in the array
          for (const item of node) {
            if (item && typeof item === "object" && seg in item) {
              next.push(item[seg]);
            }
          }
        } else if (typeof node === "object" && seg in node) {
          next.push(node[seg]);
        }
      }
    }

    if (next.length === 0) return null;
    current = next;
  }

  return current;
}

/**
 * Filters items out of the nearest array found along rule.field,
 * keeping items when evaluator returns false (remove when true).
 * Supports deep nested paths like:
 *   "cryptoTransfer.transfers.accountAmounts.accountID.alias.data"
 * Also supports simple bracket indices like: "foo.bar[0].baz"
 *
 * @param {*} root
 * @param {Array<{field:string|string[], conditions?: Array<{method:string, values?: any[]}>}>} filters
 * @param {Object.<string,(actual:any, expected:any)=>boolean>} filterEvaluators
 * @param {{ mutate?: boolean, keepWhenUndefined?: boolean }} [options]
 * @returns {*}
 */
export function applyFilterConditions(
  root,
  filters = [],
  filterEvaluators = {},
  options = {}
) {
  const { mutate = false, keepWhenUndefined = true } = options;

  // Robust-ish clone without TS: prefers structuredClone, falls back to JSON.
  const deepClone = (x) => {
    if (mutate) return x; // operate in-place if requested
    if (typeof structuredClone === "function") return structuredClone(x);
    return JSON.parse(JSON.stringify(x));
  };

  const getPath = (obj, pathArr) => {
    let cur = obj;
    for (let i = 0; i < pathArr.length; i++) {
      if (cur == null) return undefined;
      cur = cur[pathArr[i]];
    }
    return cur;
  };

  const cloned = deepClone(root);

  for (const rule of filters) {
    if (!rule || !rule.field) continue;

    const parts = splitPath(rule.field);
    if (parts.length < 2) {
      throw new Error("Invalid field path, expected at least two parts.");
    }

    // Walk down until we encounter the FIRST array — that's our container to filter.
    let ctx = cloned; // current object we’re traversing
    let containerParent = null; // parent object holding the array
    let containerKey = null; // key of the array within parent
    let containerIndex = -1; // index where the array segment lives

    for (let i = 0; i < parts.length; i++) {
      const seg = parts[i];

      if (ctx == null || !(seg in ctx)) {
        const full = Array.isArray(rule.field) ? rule.field.join(".") : rule.field;
        throw new Error(`Path segment "${seg}" not found while resolving "${full}"`);
      }

      if (Array.isArray(ctx[seg])) {
        containerParent = ctx;
        containerKey = seg;
        containerIndex = i;
        break;
      }
      ctx = ctx[seg];
    }

    if (!containerParent || containerKey == null) {
      const full = Array.isArray(rule.field) ? rule.field.join(".") : rule.field;
      throw new Error(`No array found in field path "${full}".`);
    }

    // The remaining path segments inside each item to reach the actual value
    const valuePath = parts.slice(containerIndex + 1);
    if (valuePath.length === 0) {
      const full = Array.isArray(rule.field) ? rule.field.join(".") : rule.field;
      throw new Error(`Field path "${full}" points to the array itself; append a nested key to filter on.`);
    }

    let items = containerParent[containerKey];
    if (!Array.isArray(items)) {
      throw new Error(`Expected "${containerKey}" to be an array.`);
    }

    const conditions = Array.isArray(rule.conditions) ? rule.conditions : [];
    for (const condition of conditions) {
      const evaluator = condition && filterEvaluators[condition.method];
      if (typeof evaluator !== "function") continue;

      const expectedList = Array.isArray(condition.values)
        ? condition.values
        : [condition?.values]; // tolerate undefined

      items = items.filter((item) => {
        const actual = getPath(item, valuePath);

        if (typeof actual === "undefined" && keepWhenUndefined) {
          // Keep the item when target value isn't present
          return true;
        }

        // Remove item when the evaluator returns true for ANY expected value.
        // (Change to .every(...) to require ALL values to match before removal.)
        const shouldRemove = expectedList.some((expected) => evaluator(actual, expected));
        return !shouldRemove;
      });
    }

    // Write back the filtered array
    containerParent[containerKey] = items;
  }

  return cloned;
}
