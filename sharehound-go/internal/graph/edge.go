// Package graph provides OpenGraph structures for BloodHound integration.
package graph

import (
	"encoding/json"
)

// EdgeEndpoint represents a node reference in an edge.
// Per BloodHound schema, uses "value" for the matching value.
type EdgeEndpoint struct {
	Value   string `json:"value,omitempty"`
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
		Start:      EdgeEndpoint{Value: startNodeID},
		End:        EdgeEndpoint{Value: endNodeID},
		Kind:       kind,
		Properties: make(map[string]interface{}),
	}
}

// NewEdgeByName creates a new edge matching nodes by name.
func NewEdgeByName(startName, endName, kind string) *Edge {
	return &Edge{
		Start:      EdgeEndpoint{Value: startName, MatchBy: "name"},
		End:        EdgeEndpoint{Value: endName, MatchBy: "name"},
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

// StartNode returns the start node value for backward compatibility.
func (e *Edge) StartNode() string {
	return e.Start.Value
}

// EndNode returns the end node value for backward compatibility.
func (e *Edge) EndNode() string {
	return e.End.Value
}

// MarshalJSON implements custom JSON marshaling for Edge.
func (e *Edge) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	// Build start endpoint (BloodHound schema requires "value")
	startObj := make(map[string]interface{})
	if e.Start.Value != "" {
		startObj["value"] = e.Start.Value
	}
	if e.Start.MatchBy != "" {
		startObj["match_by"] = e.Start.MatchBy
	}
	if e.Start.Kind != "" {
		startObj["kind"] = e.Start.Kind
	}
	m["start"] = startObj

	// Build end endpoint (BloodHound schema requires "value")
	endObj := make(map[string]interface{})
	if e.End.Value != "" {
		endObj["value"] = e.End.Value
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
// Supports both BloodHound schema ("value") and legacy formats ("id", "name").
func parseEndpoint(data json.RawMessage, ep *EdgeEndpoint) error {
	if len(data) == 0 {
		return nil
	}

	// Try as string first (backward compatibility)
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		ep.Value = str
		return nil
	}

	// Try as object - support both "value" and legacy "id"/"name" fields
	var obj struct {
		Value   string `json:"value,omitempty"`
		ID      string `json:"id,omitempty"`
		Name    string `json:"name,omitempty"`
		MatchBy string `json:"match_by,omitempty"`
		Kind    string `json:"kind,omitempty"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	// Use "value" if present, otherwise fall back to "id" or "name" for legacy support
	if obj.Value != "" {
		ep.Value = obj.Value
	} else if obj.ID != "" {
		ep.Value = obj.ID
	} else if obj.Name != "" {
		ep.Value = obj.Name
	}
	ep.MatchBy = obj.MatchBy
	ep.Kind = obj.Kind

	return nil
}
