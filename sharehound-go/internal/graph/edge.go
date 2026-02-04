// Package graph provides OpenGraph structures for BloodHound integration.
package graph

import (
	"encoding/json"
)

// Edge represents an edge (relationship) in the OpenGraph.
type Edge struct {
	StartNode    string                 `json:"start"`
	EndNode      string                 `json:"end"`
	Kind         string                 `json:"kind"`
	StartMatchBy string                 `json:"start_match_by,omitempty"`
	EndMatchBy   string                 `json:"end_match_by,omitempty"`
	Properties   map[string]interface{} `json:"properties,omitempty"`
}

// NewEdge creates a new edge with the given parameters.
func NewEdge(startNode, endNode, kind string) *Edge {
	return &Edge{
		StartNode:  startNode,
		EndNode:    endNode,
		Kind:       kind,
		Properties: make(map[string]interface{}),
	}
}

// SetStartMatchBy sets how to match the start node.
func (e *Edge) SetStartMatchBy(matchBy string) *Edge {
	e.StartMatchBy = matchBy
	return e
}

// SetEndMatchBy sets how to match the end node.
func (e *Edge) SetEndMatchBy(matchBy string) *Edge {
	e.EndMatchBy = matchBy
	return e
}

// SetProperty sets a property on the edge.
func (e *Edge) SetProperty(key string, value interface{}) *Edge {
	if e.Properties == nil {
		e.Properties = make(map[string]interface{})
	}
	e.Properties[key] = value
	return e
}

// MarshalJSON implements custom JSON marshaling for Edge.
func (e *Edge) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["start"] = e.StartNode
	m["end"] = e.EndNode
	m["kind"] = e.Kind

	if e.StartMatchBy != "" {
		m["start_match_by"] = e.StartMatchBy
	}
	if e.EndMatchBy != "" {
		m["end_match_by"] = e.EndMatchBy
	}
	if len(e.Properties) > 0 {
		m["properties"] = e.Properties
	}

	return json.Marshal(m)
}
