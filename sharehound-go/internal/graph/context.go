// Package graph provides OpenGraph structures for BloodHound integration.
package graph

import (
	"path/filepath"
	"strings"

	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/pkg/kinds"
)

// ShareRights maps SID to list of edge kinds.
type ShareRights map[string][]string

// PathEntry represents a directory in the path with its rights.
type PathEntry struct {
	Node   *Node
	Rights ShareRights
}

// OpenGraphContext maintains context while building the OpenGraph structure.
type OpenGraphContext struct {
	graph             *OpenGraph
	host              *Node
	share             *Node
	shareRights       ShareRights
	path              []PathEntry
	element           *Node
	elementRights     ShareRights
	logger            logger.LoggerInterface
	totalEdgesCreated int
	hostEdgeEmitted   bool                // true once host node + HostsNetworkShare have been added to graph
	hostShareEmitted  bool                // true once share node + share-rights + HasNetworkShare have been added to graph
	emittedPathNodes  map[string]struct{} // directory node IDs already committed (edges + rights)
}

// NewOpenGraphContext creates a new OpenGraphContext.
func NewOpenGraphContext(graph *OpenGraph, log logger.LoggerInterface) *OpenGraphContext {
	return &OpenGraphContext{
		graph:            graph,
		path:             make([]PathEntry, 0),
		shareRights:      make(ShareRights),
		elementRights:    make(ShareRights),
		logger:           log,
		emittedPathNodes: make(map[string]struct{}),
	}
}

// SetHost sets the host node.
func (c *OpenGraphContext) SetHost(host *Node) {
	c.host = host
}

// GetHost returns the host node.
func (c *OpenGraphContext) GetHost() *Node {
	return c.host
}

// SetShare sets the share node.
func (c *OpenGraphContext) SetShare(share *Node) {
	c.share = share
}

// GetShare returns the share node.
func (c *OpenGraphContext) GetShare() *Node {
	return c.share
}

// SetShareRights sets the share rights.
func (c *OpenGraphContext) SetShareRights(rights ShareRights) {
	c.shareRights = rights
}

// GetShareRights returns the share rights.
func (c *OpenGraphContext) GetShareRights() ShareRights {
	return c.shareRights
}

// PushPath adds a directory to the path stack.
func (c *OpenGraphContext) PushPath(node *Node, rights ShareRights) {
	c.path = append(c.path, PathEntry{Node: node, Rights: rights})
}

// PopPath removes and returns the last directory from the path stack.
func (c *OpenGraphContext) PopPath() *Node {
	if len(c.path) == 0 {
		return nil
	}
	entry := c.path[len(c.path)-1]
	c.path = c.path[:len(c.path)-1]
	return entry.Node
}

// GetPath returns the current path.
func (c *OpenGraphContext) GetPath() []PathEntry {
	return c.path
}

// ClearPath clears the path.
func (c *OpenGraphContext) ClearPath() {
	c.path = make([]PathEntry, 0)
}

// SetElement sets the current element (file or directory).
func (c *OpenGraphContext) SetElement(element *Node) {
	c.element = element
}

// GetElement returns the current element.
func (c *OpenGraphContext) GetElement() *Node {
	return c.element
}

// SetElementRights sets the element rights.
func (c *OpenGraphContext) SetElementRights(rights ShareRights) {
	if rights == nil {
		rights = make(ShareRights)
	}
	c.elementRights = rights
}

// GetElementRights returns the element rights.
func (c *OpenGraphContext) GetElementRights() ShareRights {
	return c.elementRights
}

// ClearElement clears the current element.
func (c *OpenGraphContext) ClearElement() {
	c.element = nil
	c.elementRights = make(ShareRights)
}

// SetDirectoryRights sets rights for the last directory in the path.
func (c *OpenGraphContext) SetDirectoryRights(rights ShareRights) {
	if len(c.path) > 0 && rights != nil {
		c.path[len(c.path)-1].Rights = rights
	}
}

// GetStringPathFromRoot returns the path as a string from the root.
func (c *OpenGraphContext) GetStringPathFromRoot() string {
	parts := make([]string, 0, len(c.path))
	for _, entry := range c.path {
		name := entry.Node.GetStringProperty("name")
		if name != "" {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, "\\")
}

// AddPathToGraph adds the current path structure to the graph.
func (c *OpenGraphContext) AddPathToGraph() {
	// Check host
	if c.host == nil {
		if c.logger != nil {
			c.logger.Debug("[add_path_to_graph] Host is None, skipping")
		}
		return
	}

	// Add host node and HostsNetworkShare edge before checking share.
	// This matches the Python behavior where the host node and the
	// HostsNetworkShare edge are emitted independently of the share state.
	if !c.hostEdgeEmitted {
		c.hostEdgeEmitted = true

		// Add host node
		c.graph.AddNodeWithoutValidation(c.host)

		// Add HostsNetworkShare edge from BloodHound Computer to NetworkShareHost
		hostEdge := NewEdge(strings.ToUpper(c.host.ID), c.host.ID, kinds.EdgeKindHostsNetworkShare)
		hostEdge.SetStartMatchBy("name")
		hostEdge.SetEndMatchBy("id")
		c.graph.AddEdgeWithoutValidation(hostEdge)
		c.totalEdgesCreated++

		if c.logger != nil {
			c.logger.Debug("[add_path_to_graph] Created edge HostsNetworkShare: Computer -> NetworkShareHost")
		}
	}

	// Check share
	if c.share == nil {
		if c.logger != nil {
			c.logger.Debug("[add_path_to_graph] Share node is None, skipping")
		}
		return
	}

	// Emit share structure only once per context (per share)
	if !c.hostShareEmitted {
		c.hostShareEmitted = true

		// Add share node
		c.graph.AddNodeWithoutValidation(c.share)

		// Add share rights
		c.AddRightsToGraph(c.share.ID, c.shareRights, "share")

		// Add HasNetworkShare edge from host to share
		shareEdge := NewEdge(c.host.ID, c.share.ID, kinds.EdgeKindHasNetworkShare)
		c.graph.AddEdgeWithoutValidation(shareEdge)
		c.totalEdgesCreated++

		if c.logger != nil {
			c.logger.Debug("[add_path_to_graph] Created edge HasNetworkShare: host -> share")
		}
	}

	// Add path directories with Contains edges.
	// emittedPathNodes tracks which directories have already had their
	// node, rights, and Contains edge written.  This prevents duplicate
	// edges for directories that appear in the path of multiple files.
	parentID := c.share.ID
	for _, entry := range c.path {
		if _, already := c.emittedPathNodes[entry.Node.ID]; !already {
			c.emittedPathNodes[entry.Node.ID] = struct{}{}

			c.graph.AddNodeWithoutValidation(entry.Node)
			c.AddRightsToGraph(entry.Node.ID, entry.Rights, "directory")

			containsEdge := NewEdge(parentID, entry.Node.ID, kinds.EdgeKindContains)
			c.graph.AddEdgeWithoutValidation(containsEdge)
			c.totalEdgesCreated++

			if c.logger != nil {
				c.logger.Debug("[add_path_to_graph] Created edge Contains: " + parentID + " -> " + entry.Node.ID)
			}
		}
		parentID = entry.Node.ID // always advance so child edges use the right parent
	}

	// Add element node with Contains edge
	if c.element == nil {
		return
	}

	c.graph.AddNodeWithoutValidation(c.element)
	c.AddRightsToGraph(c.element.ID, c.elementRights, "file")

	elementEdge := NewEdge(parentID, c.element.ID, kinds.EdgeKindContains)
	c.graph.AddEdgeWithoutValidation(elementEdge)
	c.totalEdgesCreated++

	if c.logger != nil {
		c.logger.Debug("[add_path_to_graph] Created edge Contains: " + parentID + " -> " + c.element.ID)
	}
}

// AddRightsToGraph adds rights edges to the graph.
func (c *OpenGraphContext) AddRightsToGraph(elementID string, rights ShareRights, elementType string) {
	if rights == nil {
		if c.logger != nil {
			c.logger.Warning("[add_rights_to_graph] Rights is None for " + elementType + ": " + elementID)
		}
		return
	}

	if len(rights) == 0 {
		if c.logger != nil {
			c.logger.Debug("[add_rights_to_graph] No rights to add for " + elementType + ": " + elementID)
		}
		return
	}

	edgesCreated := 0
	for sid, edgeKinds := range rights {
		for _, edgeKind := range edgeKinds {
			edge := NewEdge(sid, elementID, edgeKind)
			c.graph.AddEdgeWithoutValidation(edge)
			c.totalEdgesCreated++
			edgesCreated++

			if c.logger != nil {
				c.logger.Debug("[add_rights_to_graph] Created edge: " + sid + " --[" + edgeKind + "]--> " + elementID)
			}
		}
	}

	if c.logger != nil {
		c.logger.Debug("[add_rights_to_graph] Created " + string(rune(edgesCreated+'0')) + " rights edge(s)")
	}
}

// GetTotalEdgesCreated returns the total number of edges created by this context.
func (c *OpenGraphContext) GetTotalEdgesCreated() int {
	return c.totalEdgesCreated
}

// BuildUNCPath builds a UNC path from components.
func BuildUNCPath(host, share, path string) string {
	base := "\\\\" + host + "\\" + share
	if path == "" {
		return base + "\\"
	}
	return base + "\\" + filepath.ToSlash(path)
}
