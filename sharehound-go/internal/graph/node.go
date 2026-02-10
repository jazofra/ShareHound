// Package graph provides OpenGraph structures for BloodHound integration.
package graph

import (
	"encoding/json"
)

// Node represents a node in the OpenGraph.
type Node struct {
	ID         string                 `json:"id"`
	Kinds      []string               `json:"kinds,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// NewNode creates a new node with the given ID and kinds.
func NewNode(id string, kinds ...string) *Node {
	return &Node{
		ID:         id,
		Kinds:      kinds,
		Properties: make(map[string]interface{}),
	}
}

// SetProperty sets a property on the node.
func (n *Node) SetProperty(key string, value interface{}) *Node {
	if n.Properties == nil {
		n.Properties = make(map[string]interface{})
	}
	n.Properties[key] = value
	return n
}

// GetProperty gets a property from the node.
func (n *Node) GetProperty(key string) (interface{}, bool) {
	if n.Properties == nil {
		return nil, false
	}
	val, ok := n.Properties[key]
	return val, ok
}

// GetStringProperty gets a string property from the node.
func (n *Node) GetStringProperty(key string) string {
	val, ok := n.GetProperty(key)
	if !ok {
		return ""
	}
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

// MarshalJSON implements custom JSON marshaling for Node.
func (n *Node) MarshalJSON() ([]byte, error) {
	// Create a map with the node structure
	m := make(map[string]interface{})
	m["id"] = n.ID

	// BloodHound schema requires "kinds" as an array
	if len(n.Kinds) > 0 {
		m["kinds"] = n.Kinds
	}

	// Add properties
	if len(n.Properties) > 0 {
		m["properties"] = n.Properties
	}

	return json.Marshal(m)
}

// UnmarshalJSON implements custom JSON unmarshaling for Node.
func (n *Node) UnmarshalJSON(data []byte) error {
	// Use a temporary struct to parse the JSON
	// Support both "kind" (legacy) and "kinds" (BloodHound schema)
	var raw struct {
		ID         string                 `json:"id"`
		Kind       interface{}            `json:"kind"`
		Kinds      interface{}            `json:"kinds"`
		Properties map[string]interface{} `json:"properties"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	n.ID = raw.ID
	n.Properties = raw.Properties

	// Prefer "kinds" (BloodHound schema), fall back to "kind" (legacy)
	kindData := raw.Kinds
	if kindData == nil {
		kindData = raw.Kind
	}

	// Handle kind/kinds as either string or []string
	switch v := kindData.(type) {
	case string:
		n.Kinds = []string{v}
	case []interface{}:
		n.Kinds = make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				n.Kinds = append(n.Kinds, s)
			}
		}
	}

	return nil
}
