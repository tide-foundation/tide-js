import RuleEngineService from "./RuleEngineService";

/**
 * Process the rule settings for the specified key.
 * A successful rule set is one where all of its conditions pass (filter rules are applied first, then non-filter).
 * When multiple successful rule sets are found, if any include a rule with field "Outputs.Amount" that has
 * a condition with method "TOTAL_LESS_THAN", we select the rule set whose condition value (converted to a number)
 * is the lowest.
 * 
 * @param {string} key - The key to select validation settings.
 * @param {string} id - The substring that must be contained in the ruleSetId.
 * @param {RuleSettings} ruleSettings - The rule settings object.
 * @param {string} draftJson - The JSON string to evaluate.
 * @returns {{ roles: string[], threshold: number }}
 */
export default function processThresholdRules(key, id, ruleSettings, draftJson) {
  // Retrieve rule sets for the specified key.
  const ruleSets = ruleSettings.validationSettings[key];
  if (!ruleSets || ruleSets.length === 0) {
    console.warn(`No rule sets found for key "${key}".`);
    return { roles: [], threshold: 0 };
  }

  // Instantiate the rule engine.
  const ruleEngine = new RuleEngineService();
  let passingRuleSets = [];

  // Loop through each rule set.
  for (const ruleSet of ruleSets) {
    // Only consider rule sets whose ruleSetId contains the specified substring.
    if (ruleSet.ruleSetId && ruleSet.ruleSetId.includes(id)) {
      // Evaluate the rule set. 
      // evaluateRules applies its filter rules first and then evaluates the remaining conditions.
      if (ruleEngine.evaluateRules(ruleSet.rules, draftJson)) {
        // A ruleset is successful if all of its rules pass.
        // Get the threshold from outputs (if provided), converting to a number.
        const threshold = (ruleSet.outputs && ruleSet.outputs["threshold"] !== undefined)
          ? Number(ruleSet.outputs["threshold"])
          : 0;
        // Derive the role by splitting the ruleSetId; use the last segment.
        const parts = ruleSet.ruleSetId.split(".");
        const role = parts[parts.length - 1];
        passingRuleSets.push({ role, threshold, ruleSet });
      }
    }
  }

  // No rule set passed.
  if (passingRuleSets.length === 0) {
    throw new Error("No threshold rules passed");
  }

  // If multiple rule sets passed, try to find those that have a specific condition:
  // the rule definition on field "Outputs.Amount" that includes a condition with method "TOTAL_LESS_THAN".
  const passingWithTotalLessThan = passingRuleSets.filter(candidate => {
    return candidate.ruleSet.rules.some(rule =>
      rule.field === "Outputs.Amount" &&
      rule.conditions && rule.conditions.some(cond => cond.method === "TOTAL_LESS_THAN")
    );
  });

  if (passingWithTotalLessThan.length > 0) {
    // For each candidate, find the lowest processable value from its TOTAL_LESS_THAN condition.
    const evaluatedCandidates = passingWithTotalLessThan.map(candidate => {
      let processableValues = [];
      candidate.ruleSet.rules.forEach(rule => {
        // Only examine the rule if it applies to the field "Outputs.Amount".
        if (rule.field === "Outputs.Amount" && rule.conditions) {
          rule.conditions.forEach(cond => {
            if (
              cond.method === "TOTAL_LESS_THAN" &&
              Array.isArray(cond.values) &&
              cond.values.length > 0
            ) {
              const numVal = Number(cond.values[0]);
              if (!isNaN(numVal)) {
                processableValues.push(numVal);
              }
            }
          });
        }
      });
      // Determine the lowest processable value for this candidate.
      const minProcessableValue = processableValues.length > 0 ? Math.min(...processableValues) : Infinity;
      return { candidate, minProcessableValue };
    });
    // Sort candidates by the lowest processable value.
    evaluatedCandidates.sort((a, b) => a.minProcessableValue - b.minProcessableValue);
    const selected = evaluatedCandidates[0].candidate;
    return {
      roles: [selected.role],
      threshold: selected.threshold
    };
  } else {
    // Fallback: If no rule set has the specific TOTAL_LESS_THAN condition,
    // ensure that all passing rule sets have the same output threshold.
    const uniqueThresholds = new Set(passingRuleSets.map(rs => rs.threshold));
    if (uniqueThresholds.size > 1) {
      throw new Error("Conflicting thresholds found among passing rule sets.");
    }
    const roles = passingRuleSets.map(rs => rs.role);
    return {
      roles,
      threshold: passingRuleSets[0].threshold
    };
  }
}
