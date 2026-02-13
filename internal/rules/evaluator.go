// Package rules provides ShareQL rule parsing and evaluation.
package rules

import (
	"strings"
)

// EvaluationContext holds the context for rule evaluation.
type EvaluationContext struct {
	Share     *RuleObjectShare
	File      *RuleObjectFile
	Directory *RuleObjectDirectory
	Depth     int
}

// GetFieldValue returns the value of a field from the context.
func (c *EvaluationContext) GetFieldValue(field string) interface{} {
	field = strings.ToUpper(field)

	switch field {
	case "DEPTH":
		return c.Depth

	case "SHARE.NAME":
		if c.Share != nil {
			return c.Share.Name
		}
	case "SHARE.DESCRIPTION":
		if c.Share != nil {
			return c.Share.Description
		}
	case "SHARE.HIDDEN":
		if c.Share != nil {
			return c.Share.Hidden
		}

	case "FILE.NAME":
		if c.File != nil {
			return c.File.Name
		}
	case "FILE.PATH":
		if c.File != nil {
			return c.File.Path
		}
	case "FILE.SIZE":
		if c.File != nil {
			return c.File.Size
		}
	case "FILE.EXTENSION":
		if c.File != nil {
			return c.File.Extension
		}

	case "DIR.NAME", "DIRECTORY.NAME":
		if c.Directory != nil {
			return c.Directory.Name
		}
	case "DIR.PATH", "DIRECTORY.PATH":
		if c.Directory != nil {
			return c.Directory.Path
		}
	}

	return nil
}

// Evaluator evaluates rules against objects.
type Evaluator struct {
	rules   []Rule
	context *EvaluationContext
}

// NewEvaluator creates a new rule evaluator.
func NewEvaluator(rules []Rule) *Evaluator {
	return &Evaluator{
		rules:   rules,
		context: &EvaluationContext{},
	}
}

// SetShare sets the current share in the context.
func (e *Evaluator) SetShare(share *RuleObjectShare) {
	e.context.Share = share
}

// SetFile sets the current file in the context.
func (e *Evaluator) SetFile(file *RuleObjectFile) {
	e.context.File = file
}

// SetDirectory sets the current directory in the context.
func (e *Evaluator) SetDirectory(dir *RuleObjectDirectory) {
	e.context.Directory = dir
}

// SetDepth sets the current depth in the context.
func (e *Evaluator) SetDepth(depth int) {
	e.context.Depth = depth
}

// GetContext returns the evaluation context.
func (e *Evaluator) GetContext() *EvaluationContext {
	return e.context
}

// CanExplore checks if an object can be explored (for directories and shares).
func (e *Evaluator) CanExplore(obj interface{}) bool {
	// Set context based on object type
	switch v := obj.(type) {
	case *RuleObjectShare:
		e.context.Share = v
	case *RuleObjectDirectory:
		e.context.Directory = v
	}

	return e.evaluate(ScopeExploration)
}

// CanProcess checks if an object can be processed (added to graph).
func (e *Evaluator) CanProcess(obj interface{}) bool {
	// Set context based on object type
	switch v := obj.(type) {
	case *RuleObjectShare:
		e.context.Share = v
	case *RuleObjectFile:
		e.context.File = v
	case *RuleObjectDirectory:
		e.context.Directory = v
	}

	return e.evaluate(ScopeProcessing)
}

// evaluate runs the rules and returns the final decision.
func (e *Evaluator) evaluate(scope RuleScope) bool {
	// Find default behavior
	defaultAllow := true
	for _, rule := range e.rules {
		if rule.IsDefault {
			defaultAllow = rule.DefaultBehavior == ActionAllow
			break
		}
	}

	// Evaluate rules in order
	for _, rule := range e.rules {
		if rule.IsDefault {
			continue
		}

		// Check if rule applies to this scope
		if rule.Scope != ScopeAll && rule.Scope != scope {
			continue
		}

		// Evaluate condition
		if rule.Condition == nil || rule.Condition.Evaluate(e.context) {
			return rule.Action == ActionAllow
		}
	}

	return defaultAllow
}
