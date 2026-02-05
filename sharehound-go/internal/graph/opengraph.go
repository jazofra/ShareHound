// Package graph provides OpenGraph structures for BloodHound integration.
package graph

import (
	"encoding/json"
	"os"
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

// openGraphOutput represents the JSON output format.
type openGraphOutput struct {
	Data  []*Node `json:"data"`
	Edges []*Edge `json:"edges"`
}

// ExportToFile exports the graph to a JSON file.
func (g *OpenGraph) ExportToFile(filename string, includeMetadata bool) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Collect nodes
	nodes := make([]*Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}

	output := openGraphOutput{
		Data:  nodes,
		Edges: g.edges,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// ToJSON returns the graph as JSON bytes.
func (g *OpenGraph) ToJSON() ([]byte, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make([]*Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, node)
	}

	output := openGraphOutput{
		Data:  nodes,
		Edges: g.edges,
	}

	return json.MarshalIndent(output, "", "  ")
}
