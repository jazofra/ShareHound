// Package rules provides ShareQL rule parsing and evaluation.
package rules

import (
	"time"
)

// RuleObjectShare represents a share for rule evaluation.
type RuleObjectShare struct {
	Name        string
	Description string
	Hidden      bool
}

// RuleObjectFile represents a file for rule evaluation.
type RuleObjectFile struct {
	Name       string
	Path       string
	Size       int64
	Extension  string
	ModifiedAt time.Time
	CreatedAt  time.Time
}

// RuleObjectDirectory represents a directory for rule evaluation.
type RuleObjectDirectory struct {
	Name       string
	Path       string
	ModifiedAt time.Time
	CreatedAt  time.Time
}

// RuleObject is an interface for objects that can be evaluated against rules.
type RuleObject interface {
	GetName() string
	GetPath() string
}

func (s *RuleObjectShare) GetName() string     { return s.Name }
func (s *RuleObjectShare) GetPath() string     { return "" }
func (f *RuleObjectFile) GetName() string      { return f.Name }
func (f *RuleObjectFile) GetPath() string      { return f.Path }
func (d *RuleObjectDirectory) GetName() string { return d.Name }
func (d *RuleObjectDirectory) GetPath() string { return d.Path }
