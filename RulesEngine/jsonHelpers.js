/**
 * Recursively retrieves nested values from a JSON object
 * using a dot-separated field path.
 * Returns an array of values or null if the field path is not found.
 */
export function tryGetNestedValues(element, fieldPath) {
    const keys = fieldPath.split(".");
    let current = [element];
    for (const key of keys) {
      let next = [];
      for (const obj of current) {
        if (obj !== undefined && obj !== null) {
          if (Array.isArray(obj)) {
            for (const item of obj) {
              if (item && typeof item === "object" && key in item) {
                next.push(item[key]);
              }
            }
          } else if (typeof obj === "object" && key in obj) {
            next.push(obj[key]);
          }
        }
      }
      if (next.length === 0) return null;
      current = next;
    }
    return current;
  }
  
  /**
   * Applies filter conditions from the given rules onto the root JSON.
   * Clones the JSON and filters out array items that match the filter criteria.
   */
  export function applyFilterConditions(root, filters, filterEvaluators) {
    const cloned = JSON.parse(JSON.stringify(root));
    filters.forEach((rule) => {
      const fieldParts = rule.field.split(".");
      if (fieldParts.length < 2)
        throw new Error("Invalid field path, expected at least two parts.");
      const containerName = fieldParts[fieldParts.length - 2];
      const key = fieldParts[fieldParts.length - 1];
      if (!(containerName in cloned))
        throw new Error(`Container ${containerName} not found in root`);
      let items = cloned[containerName];
      if (!Array.isArray(items))
        throw new Error(`Expected ${containerName} to be an array.`);
      rule.conditions.forEach((condition) => {
        if (condition.method in filterEvaluators) {
          const evaluator = filterEvaluators[condition.method];
          const targetValue = condition.values[0];
          items = items.filter((item) => {
            if (!(key in item)) return false;
            // If evaluator returns true then the item should be removed.
            return !evaluator(item[key], targetValue);
          });
        }
      });
      cloned[containerName] = items;
    });
    return cloned;
  }
  

  