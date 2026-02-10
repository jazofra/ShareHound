// Package graph provides OpenGraph structures for BloodHound integration.
package graph

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// OpenGraph represents a BloodHound OpenGraph structure.
type OpenGraph struct {
	SourceKind string
	nodes      map[string]*Node
	edges      []*Edge
	mu         sync.RWMutex
}

// NewOpenGraph creates a new OpenGraph instance.
func NewOpenGraph(sourceKind string) *OpenGraph {
	return &OpenGraph{
		SourceKind: sourceKind,
		nodes:      make(map[string]*Node),
		edges:      make([]*Edge, 0),
	}
}

// AddNode adds a node to the graph if it doesn't exist.
func (g *OpenGraph) AddNode(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodes[node.ID]; !exists {
		g.nodes[node.ID] = node
	}
}

// AddNodeWithoutValidation adds a node without checking for duplicates.
func (g *OpenGraph) AddNodeWithoutValidation(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[node.ID] = node
}

// AddEdge adds an edge to the graph.
func (g *OpenGraph) AddEdge(edge *Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges = append(g.edges, edge)
}

// AddEdgeWithoutValidation adds an edge without validation.
func (g *OpenGraph) AddEdgeWithoutValidation(edge *Edge) {
	g.AddEdge(edge)
}

// GetNode returns a node by ID.
func (g *OpenGraph) GetNode(id string) (*Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	node, ok := g.nodes[id]
	return node, ok
}

// GetNodeCount returns the number of nodes.
func (g *OpenGraph) GetNodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// GetEdgeCount returns the number of edges.
func (g *OpenGraph) GetEdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.edges)
}

// openGraphData represents the graph portion of the output.
type openGraphData struct {
	Nodes []*Node `json:"nodes"`
	Edges []*Edge `json:"edges"`
}

// openGraphMetadata represents the metadata portion of the output.
type openGraphMetadata struct {
	SourceKind string `json:"source_kind,omitempty"`
}

// openGraphOutput represents the BloodHound OpenGraph JSON format.
type openGraphOutput struct {
	Metadata *openGraphMetadata `json:"metadata,omitempty"`
	Graph    openGraphData      `json:"graph"`
}

// ProgressFunc is a callback for export progress reporting.
// phase is a description (e.g. "Serializing nodes"), current/total are item counts.
type ProgressFunc func(phase string, current, total int)

// ExportToFile exports the graph to a JSON file in BloodHound OpenGraph format.
// If the filename ends with .zip, the output will be ZIP compressed.
// Uses streaming to handle large graphs without loading everything in memory.
func (g *OpenGraph) ExportToFile(filename string, includeMetadata bool) error {
	return g.ExportToFileWithProgress(filename, includeMetadata, nil)
}

// ExportToFileWithProgress exports the graph with progress reporting.
func (g *OpenGraph) ExportToFileWithProgress(filename string, includeMetadata bool, progress ProgressFunc) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if progress != nil {
		progress("Creating output file", 0, 0)
	}

	// Create output file
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use buffered writer for better performance
	bufWriter := bufio.NewWriterSize(file, 64*1024) // 64KB buffer

	// Determine if we should use ZIP compression
	if strings.HasSuffix(strings.ToLower(filename), ".zip") {
		if progress != nil {
			progress("Preparing ZIP archive", 0, 0)
		}

		// Create ZIP writer
		zipWriter := zip.NewWriter(bufWriter)

		// Create entry for JSON file (use base name without .zip)
		baseName := filepath.Base(filename)
		jsonName := strings.TrimSuffix(baseName, ".zip")
		if !strings.HasSuffix(jsonName, ".json") {
			jsonName += ".json"
		}

		// Create compressed entry with maximum compression
		header := &zip.FileHeader{
			Name:   jsonName,
			Method: zip.Deflate,
		}
		entryWriter, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		// Stream JSON to ZIP entry
		if err := g.streamJSON(entryWriter, includeMetadata, progress); err != nil {
			return err
		}

		if progress != nil {
			progress("Finalizing ZIP archive", 0, 0)
		}

		// Close ZIP writer
		if err := zipWriter.Close(); err != nil {
			return err
		}
	} else {
		// Regular JSON output
		if err := g.streamJSON(bufWriter, includeMetadata, progress); err != nil {
			return err
		}
	}

	if progress != nil {
		progress("Flushing to disk", 0, 0)
	}

	// Flush buffer
	return bufWriter.Flush()
}

// streamJSON writes the graph as JSON to the writer in a streaming fashion.
func (g *OpenGraph) streamJSON(w io.Writer, includeMetadata bool, progress ProgressFunc) error {
	// Start the JSON object
	if _, err := w.Write([]byte("{\n")); err != nil {
		return err
	}

	// Write metadata if requested
	if includeMetadata && g.SourceKind != "" {
		if _, err := w.Write([]byte(`  "metadata": {"source_kind": "`)); err != nil {
			return err
		}
		if _, err := w.Write([]byte(g.SourceKind)); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\"},\n")); err != nil {
			return err
		}
	}

	// Start graph object
	if _, err := w.Write([]byte("  \"graph\": {\n")); err != nil {
		return err
	}

	// Write nodes array - stream each node
	if _, err := w.Write([]byte("    \"nodes\": [\n")); err != nil {
		return err
	}

	nodeCount := 0
	totalNodes := len(g.nodes)
	// Report progress every N items to avoid excessive output
	nodeReportInterval := progressInterval(totalNodes)

	if progress != nil {
		progress("Serializing nodes", 0, totalNodes)
	}

	for _, node := range g.nodes {
		nodeJSON, err := json.Marshal(node)
		if err != nil {
			return err
		}

		if _, err := w.Write([]byte("      ")); err != nil {
			return err
		}
		if _, err := w.Write(nodeJSON); err != nil {
			return err
		}

		nodeCount++
		if nodeCount < totalNodes {
			if _, err := w.Write([]byte(",\n")); err != nil {
				return err
			}
		} else {
			if _, err := w.Write([]byte("\n")); err != nil {
				return err
			}
		}

		if progress != nil && nodeCount%nodeReportInterval == 0 {
			progress("Serializing nodes", nodeCount, totalNodes)
		}
	}

	if progress != nil {
		progress("Serializing nodes", totalNodes, totalNodes)
	}

	if _, err := w.Write([]byte("    ],\n")); err != nil {
		return err
	}

	// Write edges array - stream each edge
	if _, err := w.Write([]byte("    \"edges\": [\n")); err != nil {
		return err
	}

	totalEdges := len(g.edges)
	edgeReportInterval := progressInterval(totalEdges)

	if progress != nil {
		progress("Serializing edges", 0, totalEdges)
	}

	for i, edge := range g.edges {
		edgeJSON, err := json.Marshal(edge)
		if err != nil {
			return err
		}

		if _, err := w.Write([]byte("      ")); err != nil {
			return err
		}
		if _, err := w.Write(edgeJSON); err != nil {
			return err
		}

		if i < totalEdges-1 {
			if _, err := w.Write([]byte(",\n")); err != nil {
				return err
			}
		} else {
			if _, err := w.Write([]byte("\n")); err != nil {
				return err
			}
		}

		if progress != nil && (i+1)%edgeReportInterval == 0 {
			progress("Serializing edges", i+1, totalEdges)
		}
	}

	if progress != nil {
		progress("Serializing edges", totalEdges, totalEdges)
	}

	if _, err := w.Write([]byte("    ]\n")); err != nil {
		return err
	}

	// Close graph object
	if _, err := w.Write([]byte("  }\n")); err != nil {
		return err
	}

	// Close root object
	if _, err := w.Write([]byte("}\n")); err != nil {
		return err
	}

	return nil
}

// ToJSON returns the graph as JSON bytes in BloodHound OpenGraph format.
func (g *OpenGraph) ToJSON() ([]byte, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}

	output := openGraphOutput{
		Graph: openGraphData{
			Nodes: nodes,
			Edges: g.edges,
		},
	}

	if g.SourceKind != "" {
		output.Metadata = &openGraphMetadata{
			SourceKind: g.SourceKind,
		}
	}

	return json.MarshalIndent(output, "", "  ")
}

// progressInterval returns how often to report progress.
// Aims for roughly 20-50 updates for any collection size.
func progressInterval(total int) int {
	if total <= 0 {
		return 1
	}
	interval := total / 25
	if interval < 1 {
		interval = 1
	}
	return interval
}

// GetNodesAndEdges returns copies of all nodes and edges for checkpointing.
func (g *OpenGraph) GetNodesAndEdges() ([]*Node, []*Edge) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}

	edges := make([]*Edge, len(g.edges))
	copy(edges, g.edges)

	return nodes, edges
}

// RestoreNodesAndEdges restores nodes and edges from a checkpoint.
func (g *OpenGraph) RestoreNodesAndEdges(nodes []*Node, edges []*Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.nodes = make(map[string]*Node, len(nodes))
	for _, node := range nodes {
		g.nodes[node.ID] = node
	}

	g.edges = make([]*Edge, len(edges))
	copy(g.edges, edges)
}
