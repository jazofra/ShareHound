// Package rules provides ShareQL rule parsing and evaluation.
package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultRules contains the default rules if none are specified.
var DefaultRules = []string{
	"DEFAULT: ALLOW",
	"DENY EXPLORATION IF SHARE.NAME IN ['c$','print$','admin$','ipc$']",
	"ALLOW EXPLORATION",
}

// Parser parses ShareQL rules.
type Parser struct{}

// NewParser creates a new rule parser.
func NewParser() *Parser {
	return &Parser{}
}

// Parse parses a string containing ShareQL rules.
func (p *Parser) Parse(input string) ([]Rule, []error) {
	var rules []Rule
	var errors []error

	lines := strings.Split(input, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		rule, err := p.parseLine(line)
		if err != nil {
			errors = append(errors, fmt.Errorf("line %d: %v", i+1, err))
			continue
		}

		rules = append(rules, *rule)
	}

	return rules, errors
}

// ParseStrings parses multiple rule strings.
func (p *Parser) ParseStrings(inputs []string) ([]Rule, []error) {
	combined := strings.Join(inputs, "\n")
	return p.Parse(combined)
}

// parseLine parses a single rule line.
func (p *Parser) parseLine(line string) (*Rule, error) {
	line = strings.TrimSpace(line)
	upper := strings.ToUpper(line)

	// Check for DEFAULT rule
	if strings.HasPrefix(upper, "DEFAULT:") || strings.HasPrefix(upper, "DEFAULT :") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid DEFAULT rule")
		}
		behavior := strings.TrimSpace(strings.ToUpper(parts[1]))
		if behavior != "ALLOW" && behavior != "DENY" {
			return nil, fmt.Errorf("DEFAULT must be ALLOW or DENY, got: %s", behavior)
		}
		return &Rule{
			IsDefault:       true,
			DefaultBehavior: RuleAction(behavior),
		}, nil
	}

	// Parse action
	var action RuleAction
	remaining := line
	if strings.HasPrefix(upper, "ALLOW") {
		action = ActionAllow
		remaining = strings.TrimPrefix(line, line[:5])
	} else if strings.HasPrefix(upper, "DENY") {
		action = ActionDeny
		remaining = strings.TrimPrefix(line, line[:4])
	} else {
		return nil, fmt.Errorf("rule must start with ALLOW, DENY, or DEFAULT")
	}

	remaining = strings.TrimSpace(remaining)
	upperRemaining := strings.ToUpper(remaining)

	// Parse scope (EXPLORATION or PROCESSING)
	var scope RuleScope
	if strings.HasPrefix(upperRemaining, "EXPLORATION") {
		scope = ScopeExploration
		remaining = strings.TrimSpace(remaining[11:])
	} else if strings.HasPrefix(upperRemaining, "PROCESSING") {
		scope = ScopeProcessing
		remaining = strings.TrimSpace(remaining[10:])
	}

	// Check for IF condition
	upperRemaining = strings.ToUpper(remaining)
	if strings.HasPrefix(upperRemaining, "IF ") {
		conditionStr := strings.TrimSpace(remaining[3:])
		condition, err := p.parseCondition(conditionStr)
		if err != nil {
			return nil, fmt.Errorf("error parsing condition: %v", err)
		}
		return &Rule{
			Action:    action,
			Scope:     scope,
			Condition: condition,
		}, nil
	}

	// No condition - always true
	return &Rule{
		Action:    action,
		Scope:     scope,
		Condition: &AlwaysTrueCondition{},
	}, nil
}

// parseCondition parses a condition expression.
func (p *Parser) parseCondition(input string) (Condition, error) {
	input = strings.TrimSpace(input)

	// Check for OR
	orParts := splitAtKeyword(input, " OR ")
	if len(orParts) > 1 {
		var conditions []Condition
		for _, part := range orParts {
			cond, err := p.parseCondition(part)
			if err != nil {
				return nil, err
			}
			conditions = append(conditions, cond)
		}
		return &OrCondition{Conditions: conditions}, nil
	}

	// Check for AND
	andParts := splitAtKeyword(input, " AND ")
	if len(andParts) > 1 {
		var conditions []Condition
		for _, part := range andParts {
			cond, err := p.parseCondition(part)
			if err != nil {
				return nil, err
			}
			conditions = append(conditions, cond)
		}
		return &AndCondition{Conditions: conditions}, nil
	}

	// Check for NOT
	upper := strings.ToUpper(input)
	if strings.HasPrefix(upper, "NOT ") {
		inner, err := p.parseCondition(input[4:])
		if err != nil {
			return nil, err
		}
		return &NotCondition{Inner: inner}, nil
	}

	// Check for parentheses
	if strings.HasPrefix(input, "(") && strings.HasSuffix(input, ")") {
		return p.parseCondition(input[1 : len(input)-1])
	}

	// Parse field comparison
	return p.parseComparison(input)
}

// parseComparison parses a field comparison.
func (p *Parser) parseComparison(input string) (Condition, error) {
	input = strings.TrimSpace(input)

	// Pattern: FIELD COMPARATOR VALUE
	comparators := []string{"NOT IN", "IN", "MATCHES", "!=", "<=", ">=", "=", "<", ">"}

	for _, comp := range comparators {
		idx := strings.Index(strings.ToUpper(input), " "+comp+" ")
		if idx == -1 {
			idx = strings.Index(strings.ToUpper(input), comp)
			if idx > 0 && input[idx-1] != ' ' {
				continue
			}
		}

		if idx != -1 {
			field := strings.TrimSpace(input[:idx])
			valueStart := idx + len(comp)
			if input[idx] == ' ' {
				valueStart++
			}
			valueStr := strings.TrimSpace(input[valueStart:])

			value, err := p.parseValue(valueStr)
			if err != nil {
				return nil, err
			}

			return &FieldCondition{
				Field:      field,
				Comparator: comp,
				Value:      value,
			}, nil
		}
	}

	return nil, fmt.Errorf("could not parse comparison: %s", input)
}

// parseValue parses a value (string, number, boolean, or list).
func (p *Parser) parseValue(input string) (interface{}, error) {
	input = strings.TrimSpace(input)

	// Check for list
	if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
		inner := input[1 : len(input)-1]
		parts := splitListItems(inner)
		var values []interface{}
		for _, part := range parts {
			val, err := p.parseValue(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			values = append(values, val)
		}
		return values, nil
	}

	// Check for quoted string
	if (strings.HasPrefix(input, "'") && strings.HasSuffix(input, "'")) ||
		(strings.HasPrefix(input, "\"") && strings.HasSuffix(input, "\"")) {
		return input[1 : len(input)-1], nil
	}

	// Check for boolean
	upper := strings.ToUpper(input)
	if upper == "TRUE" {
		return true, nil
	}
	if upper == "FALSE" {
		return false, nil
	}

	// Check for number
	if matched, _ := regexp.MatchString(`^-?\d+(\.\d+)?$`, input); matched {
		var num float64
		fmt.Sscanf(input, "%f", &num)
		return num, nil
	}

	// Return as string
	return input, nil
}

// splitAtKeyword splits a string at a keyword while respecting brackets and quotes.
func splitAtKeyword(input, keyword string) []string {
	var parts []string
	var current strings.Builder
	depth := 0
	inQuote := false
	quoteChar := rune(0)

	upper := strings.ToUpper(input)
	keywordLen := len(keyword)

	i := 0
	for i < len(input) {
		c := rune(input[i])

		// Handle quotes
		if c == '\'' || c == '"' {
			if !inQuote {
				inQuote = true
				quoteChar = c
			} else if c == quoteChar {
				inQuote = false
			}
			current.WriteRune(c)
			i++
			continue
		}

		// Handle brackets
		if c == '(' || c == '[' {
			depth++
			current.WriteRune(c)
			i++
			continue
		}
		if c == ')' || c == ']' {
			depth--
			current.WriteRune(c)
			i++
			continue
		}

		// Check for keyword if not in quote and depth is 0
		if !inQuote && depth == 0 && i+keywordLen <= len(input) {
			if upper[i:i+keywordLen] == strings.ToUpper(keyword) {
				parts = append(parts, current.String())
				current.Reset()
				i += keywordLen
				continue
			}
		}

		current.WriteRune(c)
		i++
	}

	parts = append(parts, current.String())
	return parts
}

// splitListItems splits list items by comma while respecting quotes.
func splitListItems(input string) []string {
	var parts []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, c := range input {
		if c == '\'' || c == '"' {
			if !inQuote {
				inQuote = true
				quoteChar = c
			} else if c == quoteChar {
				inQuote = false
			}
			current.WriteRune(c)
			continue
		}

		if c == ',' && !inQuote {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}

		current.WriteRune(c)
	}

	parts = append(parts, current.String())
	return parts
}
