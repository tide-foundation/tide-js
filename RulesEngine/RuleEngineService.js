// RuleEngineService.js (ESM)
import { tryGetNestedValues, applyFilterConditions } from "./jsonHelpers.js";
import {
  isLessThan,
  isGreaterThan,
  isEqualTo,
  filterValuesEqualTo,
  filterValuesNotEqualTo,
  isTotalLessThan,
  isTotalMoreThan
} from "./helperFunctions.js";

export default class RuleEngineService {
  constructor() {
    // Aggregate evaluators operate on entire arrays.
    this.aggregateEvaluators = {
      TOTAL_LESS_THAN: isTotalLessThan,
      TOTAL_MORE_THAN: isTotalMoreThan,
    };
    // Per-element evaluators operate on each individual element.
    this.perElementEvaluators = {
      LESS_THAN: isLessThan,
      GREATER_THAN: isGreaterThan,
      EQUAL_TO: isEqualTo,
    };
    // Filter evaluators remove items from an array based on a condition.
    this.filterEvaluators = {
      FILTER_OUT_VALUES_NOT_EQUAL_TO: filterValuesNotEqualTo,
      FILTER_OUT_VALUES_EQUAL_TO: filterValuesEqualTo,
    };
  }

  evaluateRules(rules, input) {
    let root;
    try {
      root = JSON.parse(input);
    } catch (error) {
      console.error("Invalid JSON input.");
      return false;
    }

    const rulesWithFilter = rules.filter((rule) =>
      rule.conditions.some((c) => c.method in this.filterEvaluators)
    );
    const rulesWithoutFilter = rules.filter((rule) =>
      rule.conditions.every((c) => !(c.method in this.filterEvaluators))
    );

    let filteredRoot = root;
    if (rulesWithFilter.length > 0) {
      filteredRoot = applyFilterConditions(root, rulesWithFilter, this.filterEvaluators);
    }

    for (const rule of rulesWithoutFilter) {
      const fieldValues = tryGetNestedValues(filteredRoot, rule.field);
      if (!fieldValues) {
        console.warn(`Field '${rule.field}' not found in input JSON.`);
        return false;
      }
      if (!this.evaluateRuleConditions(rule, fieldValues)) {
        console.warn(`Rule evaluation failed for field '${rule.field}'.`);
        return false;
      }
    }
    return true;
  }

  evaluateRule(rule, input) {
    let root;
    try {
      root = JSON.parse(input);
    } catch (error) {
      console.error("Invalid JSON input.");
      return false;
    }
    let modifiedRoot = root;
    if (rule.conditions.some((c) => c.method in this.filterEvaluators)) {
      modifiedRoot = applyFilterConditions(root, [rule], this.filterEvaluators);
    }
    const fieldValues = tryGetNestedValues(modifiedRoot, rule.field);
    if (!fieldValues) {
      console.warn(`Field '${rule.field}' not found in input JSON.`);
      return false;
    }
    return this.evaluateRuleConditions(rule, fieldValues);
  }

  evaluateRuleConditions(rule, fieldValues) {
    // Evaluate aggregate conditions
    const aggregateConditions = rule.conditions.filter((c) =>
      c.method in this.aggregateEvaluators
    );
    const aggregateResult =
      aggregateConditions.length === 0 ||
      aggregateConditions.every((cond) => {
        const evaluator = this.aggregateEvaluators[cond.method];
        return evaluator(fieldValues, cond.values[0]);
      });
    // Evaluate per-element conditions: at least one element must satisfy all
    const perElementConditions = rule.conditions.filter((c) =>
      c.method in this.perElementEvaluators
    );
    const perElementResult =
      perElementConditions.length === 0 ||
      fieldValues.some((val) =>
        perElementConditions.every((cond) => {
          const evaluator = this.perElementEvaluators[cond.method];
          return evaluator(val, cond.values[0]);
        })
      );
    return aggregateResult && perElementResult;
  }
}
