package rules

import (
	"testing"
)

func TestParseDefaultRule(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		input    string
		expected RuleAction
	}{
		{"DEFAULT: ALLOW", ActionAllow},
		{"DEFAULT: DENY", ActionDeny},
		{"default: allow", ActionAllow},
		{"default: deny", ActionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			rules, errors := parser.Parse(tt.input)
			if len(errors) > 0 {
				t.Fatalf("Parse errors: %v", errors)
			}
			if len(rules) != 1 {
				t.Fatalf("Expected 1 rule, got %d", len(rules))
			}
			// DEFAULT rules store the action in DefaultBehavior, not Action
			if rules[0].DefaultBehavior != tt.expected {
				t.Errorf("Expected DefaultBehavior %v, got %v", tt.expected, rules[0].DefaultBehavior)
			}
			if !rules[0].IsDefault {
				t.Error("Expected rule to be default")
			}
		})
	}
}

func TestParseSimpleRules(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		input    string
		action   RuleAction
		scope    RuleScope
		hasError bool
	}{
		{"ALLOW EXPLORATION", ActionAllow, ScopeExploration, false},
		{"DENY EXPLORATION", ActionDeny, ScopeExploration, false},
		{"ALLOW PROCESSING", ActionAllow, ScopeProcessing, false},
		{"DENY PROCESSING", ActionDeny, ScopeProcessing, false},
		{"ALLOW", ActionAllow, ScopeAll, false},
		{"DENY", ActionDeny, ScopeAll, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			rules, errors := parser.Parse(tt.input)
			if tt.hasError {
				if len(errors) == 0 {
					t.Error("Expected error but got none")
				}
				return
			}
			if len(errors) > 0 {
				t.Fatalf("Parse errors: %v", errors)
			}
			if len(rules) != 1 {
				t.Fatalf("Expected 1 rule, got %d", len(rules))
			}
			if rules[0].Action != tt.action {
				t.Errorf("Expected action %v, got %v", tt.action, rules[0].Action)
			}
			if rules[0].Scope != tt.scope {
				t.Errorf("Expected scope %v, got %v", tt.scope, rules[0].Scope)
			}
		})
	}
}

func TestParseConditionalRules(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name     string
		input    string
		hasError bool
	}{
		{
			name:     "Share name equals",
			input:    "DENY EXPLORATION IF SHARE.NAME = 'admin$'",
			hasError: false,
		},
		{
			name:     "Share name in list",
			input:    "DENY EXPLORATION IF SHARE.NAME IN ['c$', 'admin$', 'ipc$']",
			hasError: false,
		},
		{
			name:     "File size comparison",
			input:    "DENY PROCESSING IF FILE.SIZE > 10000000",
			hasError: false,
		},
		{
			name:     "File extension matches",
			input:    "ALLOW PROCESSING IF FILE.EXTENSION IN ['.txt', '.doc', '.pdf']",
			hasError: false,
		},
		{
			name:     "Directory name check",
			input:    "DENY EXPLORATION IF DIR.NAME = 'temp'",
			hasError: false,
		},
		{
			name:     "Depth comparison",
			input:    "DENY EXPLORATION IF DEPTH > 5",
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, errors := parser.Parse(tt.input)
			if tt.hasError {
				if len(errors) == 0 {
					t.Error("Expected error but got none")
				}
				return
			}
			if len(errors) > 0 {
				t.Fatalf("Parse errors: %v", errors)
			}
			if len(rules) != 1 {
				t.Fatalf("Expected 1 rule, got %d", len(rules))
			}
			if rules[0].Condition == nil {
				t.Error("Expected rule to have condition")
			}
		})
	}
}

func TestParseMultipleRules(t *testing.T) {
	parser := NewParser()

	input := `
DEFAULT: ALLOW
DENY EXPLORATION IF SHARE.NAME IN ['c$', 'admin$', 'ipc$', 'print$']
ALLOW EXPLORATION
DENY PROCESSING IF FILE.SIZE > 100000000
`

	rules, errors := parser.Parse(input)
	if len(errors) > 0 {
		t.Fatalf("Parse errors: %v", errors)
	}
	if len(rules) != 4 {
		t.Fatalf("Expected 4 rules, got %d", len(rules))
	}

	// Verify first rule is default
	if !rules[0].IsDefault {
		t.Error("Expected first rule to be default")
	}

	// Verify second rule denies exploration with condition
	if rules[1].Action != ActionDeny || rules[1].Scope != ScopeExploration {
		t.Error("Expected second rule to be DENY EXPLORATION")
	}
	if rules[1].Condition == nil {
		t.Error("Expected second rule to have condition")
	}
}

func TestParseStrings(t *testing.T) {
	parser := NewParser()

	inputs := []string{
		"DEFAULT: ALLOW",
		"DENY EXPLORATION IF SHARE.NAME IN ['c$','print$','admin$','ipc$']",
		"ALLOW EXPLORATION",
	}

	rules, errors := parser.ParseStrings(inputs)
	if len(errors) > 0 {
		t.Fatalf("Parse errors: %v", errors)
	}
	if len(rules) != 3 {
		t.Fatalf("Expected 3 rules, got %d", len(rules))
	}
}

func TestDefaultRulesConstant(t *testing.T) {
	parser := NewParser()

	rules, errors := parser.ParseStrings(DefaultRules)
	if len(errors) > 0 {
		t.Fatalf("Parse errors with default rules: %v", errors)
	}
	if len(rules) != 3 {
		t.Fatalf("Expected 3 default rules, got %d", len(rules))
	}

	// First rule should be DEFAULT: ALLOW
	if !rules[0].IsDefault || rules[0].DefaultBehavior != ActionAllow {
		t.Error("First default rule should be DEFAULT: ALLOW")
	}

	// Second rule should deny exploration for admin shares
	if rules[1].Action != ActionDeny || rules[1].Scope != ScopeExploration {
		t.Error("Second rule should be DENY EXPLORATION")
	}

	// Third rule should allow exploration
	if rules[2].Action != ActionAllow || rules[2].Scope != ScopeExploration {
		t.Error("Third rule should be ALLOW EXPLORATION")
	}
}

func TestParseComments(t *testing.T) {
	parser := NewParser()

	input := `
# This is a comment
DEFAULT: ALLOW
# Another comment
DENY EXPLORATION IF SHARE.NAME = 'test'
`

	rules, errors := parser.Parse(input)
	if len(errors) > 0 {
		t.Fatalf("Parse errors: %v", errors)
	}
	if len(rules) != 2 {
		t.Fatalf("Expected 2 rules (comments should be ignored), got %d", len(rules))
	}
}

func TestParseInvalidRule(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		// Invalid keyword should error - must start with ALLOW, DENY, or DEFAULT
		{"Invalid keyword", "MAYBE EXPLORATION", true},
		// Missing scope is valid - parser treats it as ScopeAll with condition
		{"Missing scope with condition", "ALLOW IF SHARE.NAME = 'test'", false},
		// Invalid field is valid at parse time - field validation happens at evaluation
		{"Invalid field", "DENY EXPLORATION IF INVALID.FIELD = 'test'", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errors := parser.Parse(tt.input)
			if tt.expectError && len(errors) == 0 {
				t.Error("Expected parse error but got none")
			}
			if !tt.expectError && len(errors) > 0 {
				t.Errorf("Unexpected parse error: %v", errors)
			}
		})
	}
}
