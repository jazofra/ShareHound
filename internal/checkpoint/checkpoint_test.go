package checkpoint

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/specterops/sharehound/internal/graph"
	"github.com/specterops/sharehound/internal/targets"
)

func TestManagerMarkAndCheck(t *testing.T) {
	tempDir := t.TempDir()
	cpFile := filepath.Join(tempDir, "test.checkpoint")

	manager := NewManager(cpFile, time.Minute)

	target1 := targets.Target{Value: "192.168.1.1", Type: "ip"}
	target2 := targets.Target{Value: "192.168.1.2", Type: "ip"}

	// Initially not processed
	if manager.IsTargetProcessed(target1) {
		t.Error("Target should not be marked as processed initially")
	}

	// Mark as processed
	manager.MarkTargetProcessed(target1)

	// Now should be processed
	if !manager.IsTargetProcessed(target1) {
		t.Error("Target should be marked as processed after MarkTargetProcessed")
	}

	// Other target still not processed
	if manager.IsTargetProcessed(target2) {
		t.Error("Target2 should not be marked as processed")
	}

	// Check count
	if manager.GetProcessedCount() != 1 {
		t.Errorf("Expected 1 processed target, got %d", manager.GetProcessedCount())
	}
}

func TestManagerDisabled(t *testing.T) {
	// Empty filepath means disabled
	manager := NewManager("", time.Minute)

	if manager.IsEnabled() {
		t.Error("Manager should be disabled with empty filepath")
	}

	target := targets.Target{Value: "192.168.1.1", Type: "ip"}

	// Operations should be no-ops
	manager.MarkTargetProcessed(target)
	if manager.IsTargetProcessed(target) {
		t.Error("Disabled manager should always return false for IsTargetProcessed")
	}
}

func TestSaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	cpFile := filepath.Join(tempDir, "test.checkpoint")

	// Create a manager and mark some targets
	manager := NewManager(cpFile, time.Minute)
	target1 := targets.Target{Value: "192.168.1.1", Type: "ip"}
	target2 := targets.Target{Value: "192.168.1.2", Type: "ip"}
	manager.MarkTargetProcessed(target1)
	manager.MarkTargetProcessed(target2)

	// Create a mock graph with some nodes and edges
	og, err := graph.NewOpenGraph("test")
	if err != nil {
		t.Fatalf("Failed to create graph: %v", err)
	}
	defer og.Close()
	node1 := graph.NewNode("node1", "TestKind").SetProperty("name", "Test Node 1")
	node2 := graph.NewNode("node2", "TestKind").SetProperty("name", "Test Node 2")
	og.AddNode(node1)
	og.AddNode(node2)
	edge := graph.NewEdge("node1", "node2", "TestEdge")
	og.AddEdge(edge)

	// Save checkpoint manually
	stats := Statistics{
		Success:         5,
		Errors:          1,
		SharesTotal:     10,
		SharesProcessed: 8,
	}
	manager.saveCheckpoint(og, 100, stats)

	// Verify file exists
	if !Exists(cpFile) {
		t.Fatal("Checkpoint file should exist after save")
	}

	// Load checkpoint
	cp, err := Load(cpFile)
	if err != nil {
		t.Fatalf("Failed to load checkpoint: %v", err)
	}

	// Verify loaded data
	if len(cp.ProcessedTargets) != 2 {
		t.Errorf("Expected 2 processed targets, got %d", len(cp.ProcessedTargets))
	}
	if !cp.ProcessedTargets["192.168.1.1"] {
		t.Error("Target 192.168.1.1 should be in processed targets")
	}
	if !cp.ProcessedTargets["192.168.1.2"] {
		t.Error("Target 192.168.1.2 should be in processed targets")
	}
	if cp.TotalTargets != 100 {
		t.Errorf("Expected total targets 100, got %d", cp.TotalTargets)
	}
	if len(cp.GraphNodes) != 2 {
		t.Errorf("Expected 2 graph nodes, got %d", len(cp.GraphNodes))
	}
	if len(cp.GraphEdges) != 1 {
		t.Errorf("Expected 1 graph edge, got %d", len(cp.GraphEdges))
	}
	if cp.Statistics.Success != 5 {
		t.Errorf("Expected Success=5, got %d", cp.Statistics.Success)
	}
	if cp.Statistics.Errors != 1 {
		t.Errorf("Expected Errors=1, got %d", cp.Statistics.Errors)
	}
}

func TestRestoreFrom(t *testing.T) {
	tempDir := t.TempDir()
	cpFile := filepath.Join(tempDir, "test.checkpoint")

	// Create and save a checkpoint
	manager1 := NewManager(cpFile, time.Minute)
	target1 := targets.Target{Value: "192.168.1.1", Type: "ip"}
	target2 := targets.Target{Value: "192.168.1.2", Type: "ip"}
	manager1.MarkTargetProcessed(target1)
	manager1.MarkTargetProcessed(target2)

	og, err := graph.NewOpenGraph("test")
	if err != nil {
		t.Fatalf("Failed to create graph: %v", err)
	}
	defer og.Close()
	manager1.saveCheckpoint(og, 100, Statistics{})

	// Load and restore to a new manager
	cp, err := Load(cpFile)
	if err != nil {
		t.Fatalf("Failed to load checkpoint: %v", err)
	}

	manager2 := NewManager(cpFile, time.Minute)
	manager2.RestoreFrom(cp)

	// Verify restored data
	if !manager2.IsTargetProcessed(target1) {
		t.Error("Target1 should be marked as processed after restore")
	}
	if !manager2.IsTargetProcessed(target2) {
		t.Error("Target2 should be marked as processed after restore")
	}
	if manager2.GetProcessedCount() != 2 {
		t.Errorf("Expected 2 processed targets after restore, got %d", manager2.GetProcessedCount())
	}
}

func TestDelete(t *testing.T) {
	tempDir := t.TempDir()
	cpFile := filepath.Join(tempDir, "test.checkpoint")

	// Create a file
	if err := os.WriteFile(cpFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Verify it exists
	if !Exists(cpFile) {
		t.Fatal("Test file should exist")
	}

	// Delete it
	if err := Delete(cpFile); err != nil {
		t.Fatalf("Failed to delete checkpoint: %v", err)
	}

	// Verify it's gone
	if Exists(cpFile) {
		t.Error("Checkpoint file should not exist after delete")
	}

	// Delete non-existent file should not error
	if err := Delete(cpFile); err != nil {
		t.Errorf("Deleting non-existent file should not error: %v", err)
	}
}

func TestLoadNonExistent(t *testing.T) {
	_, err := Load("/nonexistent/path/to/checkpoint.json")
	if err == nil {
		t.Error("Loading non-existent file should return error")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	cpFile := filepath.Join(tempDir, "invalid.checkpoint")

	// Write invalid JSON
	if err := os.WriteFile(cpFile, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err := Load(cpFile)
	if err == nil {
		t.Error("Loading invalid JSON should return error")
	}
}
