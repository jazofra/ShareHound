package rules

import (
	"testing"
)

func TestEvaluatorCanExplore(t *testing.T) {
	// Parse default rules
	parser := NewParser()
	rules, _ := parser.ParseStrings(DefaultRules)

	evaluator := NewEvaluator(rules)

	tests := []struct {
		name       string
		shareName  string
		canExplore bool
	}{
		{"Regular share", "data", true},
		{"Admin share (c$)", "c$", false},
		{"Admin share (C$)", "C$", false},
		{"Admin share (admin$)", "admin$", false},
		{"Admin share (ADMIN$)", "ADMIN$", false},
		{"IPC share", "ipc$", false},
		{"Print share", "print$", false},
		{"Custom share", "myshare", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			share := &RuleObjectShare{
				Name:   tt.shareName,
				Hidden: len(tt.shareName) > 0 && tt.shareName[len(tt.shareName)-1] == '$',
			}
			evaluator.SetShare(share)

			if evaluator.CanExplore(share) != tt.canExplore {
				t.Errorf("Expected CanExplore=%v for share '%s', got %v",
					tt.canExplore, tt.shareName, !tt.canExplore)
			}
		})
	}
}

func TestEvaluatorCanProcess(t *testing.T) {
	// Create rules that deny processing for large files
	parser := NewParser()
	rules, _ := parser.Parse(`
DEFAULT: ALLOW
DENY PROCESSING IF FILE.SIZE > 10000000
`)

	evaluator := NewEvaluator(rules)

	tests := []struct {
		name       string
		fileSize   int64
		canProcess bool
	}{
		{"Small file", 1000, true},
		{"Medium file", 5000000, true},
		{"Large file", 15000000, false},
		{"At limit", 10000000, true},
		{"Just over limit", 10000001, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &RuleObjectFile{
				Name: "test.txt",
				Size: tt.fileSize,
			}

			if evaluator.CanProcess(file) != tt.canProcess {
				t.Errorf("Expected CanProcess=%v for size %d, got %v",
					tt.canProcess, tt.fileSize, !tt.canProcess)
			}
		})
	}
}

func TestEvaluatorFileExtension(t *testing.T) {
	parser := NewParser()
	rules, _ := parser.Parse(`
DEFAULT: DENY
ALLOW PROCESSING IF FILE.EXTENSION IN ['.txt', '.doc', '.pdf']
`)

	evaluator := NewEvaluator(rules)

	tests := []struct {
		name       string
		extension  string
		canProcess bool
	}{
		{"Text file", ".txt", true},
		{"Doc file", ".doc", true},
		{"PDF file", ".pdf", true},
		{"Executable", ".exe", false},
		{"No extension", "", false},
		{"Unknown extension", ".xyz", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &RuleObjectFile{
				Name:      "test" + tt.extension,
				Extension: tt.extension,
			}

			if evaluator.CanProcess(file) != tt.canProcess {
				t.Errorf("Expected CanProcess=%v for extension '%s', got %v",
					tt.canProcess, tt.extension, !tt.canProcess)
			}
		})
	}
}

func TestEvaluatorDepth(t *testing.T) {
	parser := NewParser()
	rules, _ := parser.Parse(`
DEFAULT: ALLOW
DENY EXPLORATION IF DEPTH > 3
`)

	evaluator := NewEvaluator(rules)

	tests := []struct {
		name       string
		depth      int
		canExplore bool
	}{
		{"Depth 0", 0, true},
		{"Depth 1", 1, true},
		{"Depth 3", 3, true},
		{"Depth 4", 4, false},
		{"Depth 10", 10, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator.SetDepth(tt.depth)

			dir := &RuleObjectDirectory{
				Name: "testdir",
			}

			if evaluator.CanExplore(dir) != tt.canExplore {
				t.Errorf("Expected CanExplore=%v at depth %d, got %v",
					tt.canExplore, tt.depth, !tt.canExplore)
			}
		})
	}
}

func TestEvaluatorDirectoryName(t *testing.T) {
	parser := NewParser()
	rules, _ := parser.Parse(`
DEFAULT: ALLOW
DENY EXPLORATION IF DIR.NAME IN ['temp', 'tmp', 'cache', '.git']
`)

	evaluator := NewEvaluator(rules)

	tests := []struct {
		name       string
		dirName    string
		canExplore bool
	}{
		{"Normal dir", "documents", true},
		{"Temp dir", "temp", false},
		{"Tmp dir", "tmp", false},
		{"Cache dir", "cache", false},
		{"Git dir", ".git", false},
		{"Similar but allowed", "templates", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := &RuleObjectDirectory{
				Name: tt.dirName,
			}

			if evaluator.CanExplore(dir) != tt.canExplore {
				t.Errorf("Expected CanExplore=%v for dir '%s', got %v",
					tt.canExplore, tt.dirName, !tt.canExplore)
			}
		})
	}
}

func TestEvaluatorDefaultDeny(t *testing.T) {
	parser := NewParser()
	rules, _ := parser.Parse(`DEFAULT: DENY`)

	evaluator := NewEvaluator(rules)

	share := &RuleObjectShare{Name: "anyshare"}
	file := &RuleObjectFile{Name: "anyfile.txt"}
	dir := &RuleObjectDirectory{Name: "anydir"}

	// With DEFAULT: DENY, everything should be denied
	if evaluator.CanExplore(share) {
		t.Error("Expected CanExplore=false for share with DEFAULT: DENY")
	}
	if evaluator.CanProcess(file) {
		t.Error("Expected CanProcess=false for file with DEFAULT: DENY")
	}
	if evaluator.CanExplore(dir) {
		t.Error("Expected CanExplore=false for dir with DEFAULT: DENY")
	}
}

func TestEvaluatorComplexRules(t *testing.T) {
	parser := NewParser()
	rules, _ := parser.Parse(`
DEFAULT: DENY
ALLOW EXPLORATION IF SHARE.NAME = 'public'
ALLOW PROCESSING IF FILE.SIZE < 1000000
DENY EXPLORATION IF DEPTH > 2
`)

	evaluator := NewEvaluator(rules)

	// Test share exploration
	publicShare := &RuleObjectShare{Name: "public"}
	privateShare := &RuleObjectShare{Name: "private"}

	if !evaluator.CanExplore(publicShare) {
		t.Error("Expected public share to be explorable")
	}
	if evaluator.CanExplore(privateShare) {
		t.Error("Expected private share to not be explorable")
	}

	// Test file processing
	smallFile := &RuleObjectFile{Name: "small.txt", Size: 500000}
	largeFile := &RuleObjectFile{Name: "large.txt", Size: 2000000}

	if !evaluator.CanProcess(smallFile) {
		t.Error("Expected small file to be processable")
	}
	if evaluator.CanProcess(largeFile) {
		t.Error("Expected large file to not be processable")
	}

	// Test depth - with DEFAULT: DENY and no explicit ALLOW for directories,
	// directories are denied by default. The DENY EXPLORATION IF DEPTH > 2
	// rule only adds additional denial for deep dirs, but doesn't allow others.
	evaluator.SetDepth(1)
	dir := &RuleObjectDirectory{Name: "test"}
	// With DEFAULT: DENY and no ALLOW rule for directories, this is denied
	if evaluator.CanExplore(dir) {
		t.Error("Expected dir to not be explorable with DEFAULT: DENY")
	}

	evaluator.SetDepth(3)
	if evaluator.CanExplore(dir) {
		t.Error("Expected dir at depth 3 to not be explorable")
	}
}
