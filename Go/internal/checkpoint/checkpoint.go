// Package checkpoint provides scan state persistence for resumable scans.
package checkpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/specterops/sharehound/internal/graph"
	"github.com/specterops/sharehound/internal/targets"
)

// Checkpoint represents a saved scan state.
type Checkpoint struct {
	Version          string          `json:"version"`
	Timestamp        time.Time       `json:"timestamp"`
	ProcessedTargets map[string]bool `json:"processed_targets"`
	TotalTargets     int             `json:"total_targets"`
	GraphNodes       []*graph.Node   `json:"nodes"`
	GraphEdges       []*graph.Edge   `json:"edges"`
	Statistics       Statistics      `json:"statistics"`
}

// Statistics holds checkpoint statistics.
type Statistics struct {
	Success              int64 `json:"success"`
	Errors               int64 `json:"errors"`
	SharesTotal          int64 `json:"shares_total"`
	SharesProcessed      int64 `json:"shares_processed"`
	FilesTotal           int64 `json:"files_total"`
	FilesProcessed       int64 `json:"files_processed"`
	DirectoriesTotal     int64 `json:"directories_total"`
	DirectoriesProcessed int64 `json:"directories_processed"`
}

// Manager manages checkpointing operations.
type Manager struct {
	filepath         string
	interval         time.Duration
	processedTargets map[string]bool
	mu               sync.RWMutex
	stopChan         chan struct{}
	saveChan         chan struct{}
	wg               sync.WaitGroup
	enabled          bool
}

// NewManager creates a new checkpoint manager.
func NewManager(filepath string, interval time.Duration) *Manager {
	return &Manager{
		filepath:         filepath,
		interval:         interval,
		processedTargets: make(map[string]bool),
		stopChan:         make(chan struct{}),
		saveChan:         make(chan struct{}, 1),
		enabled:          filepath != "",
	}
}

// IsEnabled returns whether checkpointing is enabled.
func (m *Manager) IsEnabled() bool {
	return m.enabled
}

// GetFilepath returns the checkpoint file path.
func (m *Manager) GetFilepath() string {
	return m.filepath
}

// MarkTargetProcessed marks a target as processed.
func (m *Manager) MarkTargetProcessed(target targets.Target) {
	if !m.enabled {
		return
	}
	m.mu.Lock()
	m.processedTargets[target.Value] = true
	m.mu.Unlock()
}

// IsTargetProcessed checks if a target has been processed.
func (m *Manager) IsTargetProcessed(target targets.Target) bool {
	if !m.enabled {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.processedTargets[target.Value]
}

// GetProcessedCount returns the number of processed targets.
func (m *Manager) GetProcessedCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.processedTargets)
}

// Start begins periodic checkpointing.
func (m *Manager) Start(og *graph.OpenGraph, totalTargets int, getStats func() Statistics) {
	if !m.enabled || m.interval <= 0 {
		return
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()

		for {
			select {
			case <-m.stopChan:
				// Final save before exiting
				m.saveCheckpoint(og, totalTargets, getStats())
				return
			case <-ticker.C:
				m.saveCheckpoint(og, totalTargets, getStats())
			case <-m.saveChan:
				m.saveCheckpoint(og, totalTargets, getStats())
			}
		}
	}()
}

// Stop stops the checkpoint manager and saves final state.
func (m *Manager) Stop() {
	if !m.enabled {
		return
	}
	close(m.stopChan)
	m.wg.Wait()
}

// TriggerSave triggers an immediate checkpoint save.
func (m *Manager) TriggerSave() {
	if !m.enabled {
		return
	}
	select {
	case m.saveChan <- struct{}{}:
	default:
		// Already pending save
	}
}

// saveCheckpoint saves the current state to disk.
func (m *Manager) saveCheckpoint(og *graph.OpenGraph, totalTargets int, stats Statistics) error {
	if !m.enabled {
		return nil
	}

	m.mu.RLock()
	processed := make(map[string]bool)
	for k, v := range m.processedTargets {
		processed[k] = v
	}
	m.mu.RUnlock()

	fmt.Fprintf(os.Stderr, "\r\033[K    [Checkpoint] Copying graph data (%d processed targets)...\n", len(processed))
	nodes, edges := og.GetNodesAndEdges()

	cp := &Checkpoint{
		Version:          "1.0.0",
		Timestamp:        time.Now(),
		ProcessedTargets: processed,
		TotalTargets:     totalTargets,
		GraphNodes:       nodes,
		GraphEdges:       edges,
		Statistics:       stats,
	}

	fmt.Fprintf(os.Stderr, "    [Checkpoint] Serializing %d nodes, %d edges...\n", len(nodes), len(edges))
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	fmt.Fprintf(os.Stderr, "    [Checkpoint] Writing %s to disk...\n", formatBytes(int64(len(data))))
	// Write to temp file first, then rename (atomic)
	tempFile := m.filepath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write checkpoint: %w", err)
	}

	if err := os.Rename(tempFile, m.filepath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename checkpoint file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "    [Checkpoint] Saved successfully\n")
	return nil
}

// formatBytes formats a byte count as a human-readable string.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Load loads a checkpoint from disk.
func Load(filepath string) (*Checkpoint, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint file: %w", err)
	}

	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint file: %w", err)
	}

	return &cp, nil
}

// Exists checks if a checkpoint file exists.
func Exists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil
}

// RestoreToManager restores a checkpoint to a manager.
func (m *Manager) RestoreFrom(cp *Checkpoint) {
	m.mu.Lock()
	m.processedTargets = cp.ProcessedTargets
	m.mu.Unlock()
}

// Delete removes the checkpoint file.
func Delete(filepath string) error {
	if err := os.Remove(filepath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete checkpoint file: %w", err)
	}
	return nil
}
