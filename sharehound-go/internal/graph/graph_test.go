package graph

import (
	"encoding/json"
	"testing"
)

func TestNodeMarshalJSON(t *testing.T) {
	node := NewNode("test-id", "NetworkShare", "Base")
	node.SetProperty("name", "Share1")
	node.SetProperty("path", "\\\\server\\share")

	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("Failed to marshal node: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse marshaled JSON: %v", err)
	}

	// Verify "id" field
	if id, ok := parsed["id"].(string); !ok || id != "test-id" {
		t.Errorf("Expected id='test-id', got %v", parsed["id"])
	}

	// Verify "kinds" is an array (BloodHound schema requirement)
	kinds, ok := parsed["kinds"].([]interface{})
	if !ok {
		t.Fatalf("Expected 'kinds' to be an array, got %T", parsed["kinds"])
	}
	if len(kinds) != 2 {
		t.Errorf("Expected 2 kinds, got %d", len(kinds))
	}
	if kinds[0].(string) != "NetworkShare" || kinds[1].(string) != "Base" {
		t.Errorf("Unexpected kinds: %v", kinds)
	}

	// Verify properties
	props, ok := parsed["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'properties' to be an object, got %T", parsed["properties"])
	}
	if props["name"].(string) != "Share1" {
		t.Errorf("Expected name='Share1', got %v", props["name"])
	}
}

func TestNodeUnmarshalJSON(t *testing.T) {
	// Test with "kinds" array (BloodHound schema)
	jsonWithKinds := `{"id":"node1","kinds":["TypeA","TypeB"],"properties":{"key":"value"}}`
	var node1 Node
	if err := json.Unmarshal([]byte(jsonWithKinds), &node1); err != nil {
		t.Fatalf("Failed to unmarshal node with kinds: %v", err)
	}
	if node1.ID != "node1" {
		t.Errorf("Expected ID='node1', got %s", node1.ID)
	}
	if len(node1.Kinds) != 2 || node1.Kinds[0] != "TypeA" || node1.Kinds[1] != "TypeB" {
		t.Errorf("Expected kinds [TypeA, TypeB], got %v", node1.Kinds)
	}

	// Test with "kind" string (legacy format)
	jsonWithKind := `{"id":"node2","kind":"SingleType","properties":{}}`
	var node2 Node
	if err := json.Unmarshal([]byte(jsonWithKind), &node2); err != nil {
		t.Fatalf("Failed to unmarshal node with kind: %v", err)
	}
	if len(node2.Kinds) != 1 || node2.Kinds[0] != "SingleType" {
		t.Errorf("Expected kinds [SingleType], got %v", node2.Kinds)
	}
}

func TestEdgeMarshalJSON(t *testing.T) {
	edge := NewEdge("node1", "node2", "HasAccess")
	edge.SetProperty("permissions", "read,write")

	data, err := json.Marshal(edge)
	if err != nil {
		t.Fatalf("Failed to marshal edge: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse marshaled JSON: %v", err)
	}

	// Verify "start" is an object with "id" (BloodHound schema)
	start, ok := parsed["start"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'start' to be an object, got %T", parsed["start"])
	}
	if start["id"].(string) != "node1" {
		t.Errorf("Expected start.id='node1', got %v", start["id"])
	}

	// Verify "end" is an object with "id"
	end, ok := parsed["end"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'end' to be an object, got %T", parsed["end"])
	}
	if end["id"].(string) != "node2" {
		t.Errorf("Expected end.id='node2', got %v", end["id"])
	}

	// Verify "kind"
	if kind, ok := parsed["kind"].(string); !ok || kind != "HasAccess" {
		t.Errorf("Expected kind='HasAccess', got %v", parsed["kind"])
	}
}

func TestEdgeUnmarshalJSON(t *testing.T) {
	// Test with object format (BloodHound schema)
	jsonEdge := `{"start":{"id":"a"},"end":{"id":"b"},"kind":"Related","properties":{"weight":5}}`
	var edge1 Edge
	if err := json.Unmarshal([]byte(jsonEdge), &edge1); err != nil {
		t.Fatalf("Failed to unmarshal edge: %v", err)
	}
	if edge1.Start.ID != "a" {
		t.Errorf("Expected start.id='a', got %s", edge1.Start.ID)
	}
	if edge1.End.ID != "b" {
		t.Errorf("Expected end.id='b', got %s", edge1.End.ID)
	}
	if edge1.Kind != "Related" {
		t.Errorf("Expected kind='Related', got %s", edge1.Kind)
	}

	// Test with string format (legacy/backward compatibility)
	jsonLegacy := `{"start":"x","end":"y","kind":"Connected"}`
	var edge2 Edge
	if err := json.Unmarshal([]byte(jsonLegacy), &edge2); err != nil {
		t.Fatalf("Failed to unmarshal legacy edge: %v", err)
	}
	if edge2.Start.ID != "x" {
		t.Errorf("Expected start.id='x', got %s", edge2.Start.ID)
	}
	if edge2.End.ID != "y" {
		t.Errorf("Expected end.id='y', got %s", edge2.End.ID)
	}
}

func TestOpenGraphOutputFormat(t *testing.T) {
	og := NewOpenGraph("ShareHound")

	node1 := NewNode("share1", "NetworkShare")
	node1.SetProperty("name", "DataShare")
	og.AddNode(node1)

	node2 := NewNode("user1", "User")
	node2.SetProperty("name", "DOMAIN\\user")
	og.AddNode(node2)

	edge := NewEdge("user1", "share1", "CanRead")
	og.AddEdge(edge)

	data, err := og.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize graph: %v", err)
	}

	var output map[string]interface{}
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	// Verify BloodHound schema structure
	// 1. Must have "graph" object
	graph, ok := output["graph"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'graph' object in output, got %T", output["graph"])
	}

	// 2. Graph must have "nodes" array
	nodes, ok := graph["nodes"].([]interface{})
	if !ok {
		t.Fatalf("Expected 'graph.nodes' array, got %T", graph["nodes"])
	}
	if len(nodes) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(nodes))
	}

	// 3. Graph must have "edges" array
	edges, ok := graph["edges"].([]interface{})
	if !ok {
		t.Fatalf("Expected 'graph.edges' array, got %T", graph["edges"])
	}
	if len(edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(edges))
	}

	// 4. Should have metadata with source_kind
	metadata, ok := output["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'metadata' object, got %T", output["metadata"])
	}
	if metadata["source_kind"].(string) != "ShareHound" {
		t.Errorf("Expected source_kind='ShareHound', got %v", metadata["source_kind"])
	}

	// 5. Verify node structure in output
	node := nodes[0].(map[string]interface{})
	if _, ok := node["id"]; !ok {
		t.Error("Node missing 'id' field")
	}
	if _, ok := node["kinds"]; !ok {
		t.Error("Node missing 'kinds' field")
	}

	// 6. Verify edge structure in output
	edgeOut := edges[0].(map[string]interface{})
	startObj, ok := edgeOut["start"].(map[string]interface{})
	if !ok {
		t.Fatal("Edge 'start' should be an object")
	}
	if _, ok := startObj["id"]; !ok {
		t.Error("Edge start missing 'id' field")
	}
}
