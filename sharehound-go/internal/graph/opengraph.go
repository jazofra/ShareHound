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

// ExportToFile exports the graph to a JSON file in BloodHound OpenGraph format.
func (g *OpenGraph) ExportToFile(filename string, includeMetadata bool) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	// Collect nodes
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

	// Include metadata if requested and source kind is set
	if includeMetadata && g.SourceKind != "" {
		output.Metadata = &openGraphMetadata{
			SourceKind: g.SourceKind,
		}
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
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
