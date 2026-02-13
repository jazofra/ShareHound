// Package rules provides ShareQL rule parsing and evaluation.
package rules

import (
	"regexp"
	"strings"
)

// RuleAction represents the action of a rule.
type RuleAction string

const (
	ActionAllow RuleAction = "ALLOW"
	ActionDeny  RuleAction = "DENY"
)

// RuleScope represents what the rule applies to.
type RuleScope string

const (
	ScopeExploration RuleScope = "EXPLORATION"
	ScopeProcessing  RuleScope = "PROCESSING"
	ScopeAll         RuleScope = ""
)

// Rule represents a parsed ShareQL rule.
type Rule struct {
	IsDefault       bool
	DefaultBehavior RuleAction
	Action          RuleAction
	Scope           RuleScope
	Condition       Condition
}

// Condition represents a rule condition.
type Condition interface {
	Evaluate(ctx *EvaluationContext) bool
}

// AlwaysTrueCondition always returns true.
type AlwaysTrueCondition struct{}

func (c *AlwaysTrueCondition) Evaluate(ctx *EvaluationContext) bool {
	return true
}

// FieldCondition compares a field against a value.
type FieldCondition struct {
	Field      string
	Comparator string
	Value      interface{}
}

func (c *FieldCondition) Evaluate(ctx *EvaluationContext) bool {
	// Get the field value from context
	fieldValue := ctx.GetFieldValue(c.Field)

	// Compare based on comparator
	switch c.Comparator {
	case "=", "==":
		return compareEqual(fieldValue, c.Value)
	case "!=":
		return !compareEqual(fieldValue, c.Value)
	case "<":
		return compareLess(fieldValue, c.Value)
	case ">":
		return compareGreater(fieldValue, c.Value)
	case "<=":
		return compareLess(fieldValue, c.Value) || compareEqual(fieldValue, c.Value)
	case ">=":
		return compareGreater(fieldValue, c.Value) || compareEqual(fieldValue, c.Value)
	case "IN":
		return compareIn(fieldValue, c.Value)
	case "NOT IN":
		return !compareIn(fieldValue, c.Value)
	case "MATCHES":
		return compareMatches(fieldValue, c.Value)
	default:
		return false
	}
}

// NotCondition negates a condition.
type NotCondition struct {
	Inner Condition
}

func (c *NotCondition) Evaluate(ctx *EvaluationContext) bool {
	return !c.Inner.Evaluate(ctx)
}

// AndCondition combines conditions with AND.
type AndCondition struct {
	Conditions []Condition
}

func (c *AndCondition) Evaluate(ctx *EvaluationContext) bool {
	for _, cond := range c.Conditions {
		if !cond.Evaluate(ctx) {
			return false
		}
	}
	return true
}

// OrCondition combines conditions with OR.
type OrCondition struct {
	Conditions []Condition
}

func (c *OrCondition) Evaluate(ctx *EvaluationContext) bool {
	for _, cond := range c.Conditions {
		if cond.Evaluate(ctx) {
			return true
		}
	}
	return false
}

// Helper comparison functions
func compareEqual(a, b interface{}) bool {
	// Convert both to strings for comparison
	aStr := toString(a)
	bStr := toString(b)
	return strings.EqualFold(aStr, bStr)
}

func compareLess(a, b interface{}) bool {
	aNum, aOk := toNumber(a)
	bNum, bOk := toNumber(b)
	if aOk && bOk {
		return aNum < bNum
	}
	return false
}

func compareGreater(a, b interface{}) bool {
	aNum, aOk := toNumber(a)
	bNum, bOk := toNumber(b)
	if aOk && bOk {
		return aNum > bNum
	}
	return false
}

func compareIn(value, list interface{}) bool {
	listSlice, ok := list.([]interface{})
	if !ok {
		listStrSlice, ok := list.([]string)
		if ok {
			listSlice = make([]interface{}, len(listStrSlice))
			for i, s := range listStrSlice {
				listSlice[i] = s
			}
		} else {
			return false
		}
	}

	for _, item := range listSlice {
		if compareEqual(value, item) {
			return true
		}
	}
	return false
}

func compareMatches(value, pattern interface{}) bool {
	valueStr := toString(value)
	patternStr := toString(pattern)

	re, err := regexp.Compile(patternStr)
	if err != nil {
		return false
	}

	return re.MatchString(valueStr)
}

func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case int:
		return string(rune(val))
	case int64:
		return string(rune(val))
	case float64:
		return string(rune(int(val)))
	case bool:
		if val {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func toNumber(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case float64:
		return val, true
	case string:
		// Try to parse as number
		var num float64
		if _, err := strings.NewReader(val).Read([]byte{}); err == nil {
			return num, true
		}
		return 0, false
	default:
		return 0, false
	}
}
