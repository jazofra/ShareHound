// Package graph provides OpenGraph structures for BloodHound integration.
package graph

import (
	"encoding/json"
)

// EdgeEndpoint represents a node reference in an edge.
type EdgeEndpoint struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	MatchBy string `json:"match_by,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

// Edge represents an edge (relationship) in the OpenGraph.
type Edge struct {
	Start      EdgeEndpoint           `json:"start"`
	End        EdgeEndpoint           `json:"end"`
	Kind       string                 `json:"kind"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// NewEdge creates a new edge with the given parameters.
func NewEdge(startNodeID, endNodeID, kind string) *Edge {
	return &Edge{
		Start:      EdgeEndpoint{ID: startNodeID},
		End:        EdgeEndpoint{ID: endNodeID},
		Kind:       kind,
		Properties: make(map[string]interface{}),
	}
}

// NewEdgeByName creates a new edge matching nodes by name.
func NewEdgeByName(startName, endName, kind string) *Edge {
	return &Edge{
		Start:      EdgeEndpoint{Name: startName, MatchBy: "name"},
		End:        EdgeEndpoint{Name: endName, MatchBy: "name"},
		Kind:       kind,
		Properties: make(map[string]interface{}),
	}
}

// SetStartMatchBy sets how to match the start node.
func (e *Edge) SetStartMatchBy(matchBy string) *Edge {
	e.Start.MatchBy = matchBy
	return e
}

// SetEndMatchBy sets how to match the end node.
func (e *Edge) SetEndMatchBy(matchBy string) *Edge {
	e.End.MatchBy = matchBy
	return e
}

// SetStartKind sets the kind filter for start node matching.
func (e *Edge) SetStartKind(kind string) *Edge {
	e.Start.Kind = kind
	return e
}

// SetEndKind sets the kind filter for end node matching.
func (e *Edge) SetEndKind(kind string) *Edge {
	e.End.Kind = kind
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

// StartNode returns the start node ID for backward compatibility.
func (e *Edge) StartNode() string {
	if e.Start.ID != "" {
		return e.Start.ID
	}
	return e.Start.Name
}

// EndNode returns the end node ID for backward compatibility.
func (e *Edge) EndNode() string {
	if e.End.ID != "" {
		return e.End.ID
	}
	return e.End.Name
}

// MarshalJSON implements custom JSON marshaling for Edge.
func (e *Edge) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	// Build start endpoint
	startObj := make(map[string]interface{})
	if e.Start.ID != "" {
		startObj["id"] = e.Start.ID
	}
	if e.Start.Name != "" {
		startObj["name"] = e.Start.Name
	}
	if e.Start.MatchBy != "" {
		startObj["match_by"] = e.Start.MatchBy
	}
	if e.Start.Kind != "" {
		startObj["kind"] = e.Start.Kind
	}
	m["start"] = startObj

	// Build end endpoint
	endObj := make(map[string]interface{})
	if e.End.ID != "" {
		endObj["id"] = e.End.ID
	}
	if e.End.Name != "" {
		endObj["name"] = e.End.Name
	}
	if e.End.MatchBy != "" {
		endObj["match_by"] = e.End.MatchBy
	}
	if e.End.Kind != "" {
		endObj["kind"] = e.End.Kind
	}
	m["end"] = endObj

	m["kind"] = e.Kind

	if len(e.Properties) > 0 {
		m["properties"] = e.Properties
	}

	return json.Marshal(m)
}

// UnmarshalJSON implements custom JSON unmarshaling for Edge.
func (e *Edge) UnmarshalJSON(data []byte) error {
	var raw struct {
		Start      json.RawMessage        `json:"start"`
		End        json.RawMessage        `json:"end"`
		Kind       string                 `json:"kind"`
		Properties map[string]interface{} `json:"properties"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	e.Kind = raw.Kind
	e.Properties = raw.Properties

	// Parse start - can be string or object
	if err := parseEndpoint(raw.Start, &e.Start); err != nil {
		return err
	}

	// Parse end - can be string or object
	if err := parseEndpoint(raw.End, &e.End); err != nil {
		return err
	}

	return nil
}

// parseEndpoint parses an endpoint that can be a string or object.
func parseEndpoint(data json.RawMessage, ep *EdgeEndpoint) error {
	if len(data) == 0 {
		return nil
	}

	// Try as string first (backward compatibility)
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		ep.ID = str
		return nil
	}

	// Try as object
	var obj EdgeEndpoint
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*ep = obj
	return nil
}
