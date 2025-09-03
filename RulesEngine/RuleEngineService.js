import { tryGetNestedValues, applyFilterConditions } from "./jsonHelpers.js";
import {
  isLessThan,
  isGreaterThan,
  isEqualTo,
  filterValuesEqualTo,
  filterValuesNotEqualTo,
  isTotalLessThan,
  isTotalMoreThan,
  isHederaTotalLessThan,
  isHederaTotalMoreThan,
  isHederaTransactionLessThan,
  isHederaTransactionMoreThan,
} from "./helperFunctions.js";

export default class RuleEngineService {
  constructor() {
    // Aggregate evaluators operate on entire arrays.
    this.aggregateEvaluators = Object.freeze({
      TOTAL_LESS_THAN: isTotalLessThan,
      TOTAL_MORE_THAN: isTotalMoreThan,
      HEDERA_TOTAL_LESS_THAN: isHederaTotalLessThan,
      HEDERA_TOTAL_MORE_THAN: isHederaTotalMoreThan,
    });

    // Per-element evaluators operate on each individual element.
    this.perElementEvaluators = Object.freeze({
      LESS_THAN: isLessThan,
      GREATER_THAN: isGreaterThan,
      EQUAL_TO: isEqualTo,
      HEDERA_LESS_THAN: isHederaTransactionLessThan,
      HEDERA_GREATER_THAN: isHederaTransactionMoreThan,
    });

    // Filter evaluators remove items from an array based on a condition.
    // (applyFilterConditions will remove an item when ANY cond.values entry matches.)
    this.filterEvaluators = Object.freeze({
      FILTER_OUT_VALUES_NOT_EQUAL_TO: filterValuesNotEqualTo,
      FILTER_OUT_VALUES_EQUAL_TO: filterValuesEqualTo,
    });
  }

  evaluateRules(rules, input) {
    let root;
    try {
      root = JSON.parse(input);
    } catch {
      console.error("Invalid JSON input.");
      return false;
    }

    const rulesWithFilter = rules.filter((r) =>
      r.conditions?.some((c) => c?.method in this.filterEvaluators)
    );
    const rulesWithoutFilter = rules.filter((r) =>
      r.conditions?.every((c) => !(c?.method in this.filterEvaluators))
    );

    let filteredRoot = root;
    if (rulesWithFilter.length > 0) {
      filteredRoot = applyFilterConditions(filteredRoot, rulesWithFilter, this.filterEvaluators);
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
    } catch {
      console.error("Invalid JSON input.");
      return false;
    }

    let snapshot = root;
    if (rule.conditions?.some((c) => c?.method in this.filterEvaluators)) {
      snapshot = applyFilterConditions(snapshot, [rule], this.filterEvaluators);
    }

    const fieldValues = tryGetNestedValues(snapshot, rule.field);
    if (!fieldValues) {
      console.warn(`Field '${rule.field}' not found in input JSON.`);
      return false;
    }
    return this.evaluateRuleConditions(rule, fieldValues);
  }

  evaluateRuleConditions(rule, fieldValues) {
    // Aggregate conditions (operate on the whole list)
    const aggregateConds = rule.conditions?.filter((c) => c?.method in this.aggregateEvaluators) ?? [];
    const aggregateResult =
      aggregateConds.length === 0 ||
      aggregateConds.every((cond) => {
        const evaluator = this.aggregateEvaluators[cond.method];
        if (typeof evaluator !== "function") return false;
        return evaluator(fieldValues, firstValue(cond.values));
      });

    // Per-element conditions (ANY element must satisfy ALL per-element conditions)
    const perElementConds = rule.conditions?.filter((c) => c?.method in this.perElementEvaluators) ?? [];
    const perElementResult =
      perElementConds.length === 0 ||
      fieldValues.some((val) =>
        perElementConds.every((cond) => {
          const evaluator = this.perElementEvaluators[cond.method];
          if (typeof evaluator !== "function") return false;
          return evaluator(val, firstValue(cond.values));
        })
      );

    return aggregateResult && perElementResult;
  }
}

/* -------------------- small helpers -------------------- */

function firstValue(values) {
  // For aggregate/per-element evaluators we keep parity with your C#:
  // use only the first expected value (filtering logic already handles ANY internally).
  return Array.isArray(values) ? values[0] : undefined;
}
