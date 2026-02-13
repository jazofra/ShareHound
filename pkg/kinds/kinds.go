// Package kinds defines all node and edge type constants for the ShareHound graph.
// These must match exactly with the Python implementation for BloodHound compatibility.
package kinds

// Base node kind
const NodeKindNetworkShareBase = "NetworkShareBase"

// Host and share node kinds
const (
	NodeKindNetworkShareHost = "NetworkShareHost"
	NodeKindNetworkShareDFS  = "NetworkShareDFS"
	NodeKindNetworkShareSMB  = "NetworkShareSMB"
)

// Content node kinds
const (
	NodeKindFile      = "File"
	NodeKindDirectory = "Directory"
)

// Principal node kinds (referenced from AD)
const (
	NodeKindPrincipal = "Principal"
	NodeKindUser      = "User"
	NodeKindGroup     = "Group"
)

// Containment edge kinds
const (
	EdgeKindHasNetworkShare   = "HasNetworkShare"
	EdgeKindHostsNetworkShare = "HostsNetworkShare"
	EdgeKindContains          = "Contains"
)

// Share-level permission edge kinds - Generic rights
const (
	EdgeKindCanGenericExecute = "CanGenericExecute"
	EdgeKindCanGenericWrite   = "CanGenericWrite"
	EdgeKindCanGenericRead    = "CanGenericRead"
	EdgeKindCanGenericAll     = "CanGenericAll"
)

// Share-level permission edge kinds - Directory Service rights
const (
	EdgeKindCanDsCreateChild             = "CanDsCreateChild"
	EdgeKindCanDsDeleteChild             = "CanDsDeleteChild"
	EdgeKindCanDsListContents            = "CanDsListContents"
	EdgeKindCanDsWriteExtendedProperties = "CanDsWriteExtendedProperties"
	EdgeKindCanDsReadProperty            = "CanDsReadProperty"
	EdgeKindCanDsWriteProperty           = "CanDsWriteProperty"
	EdgeKindCanDsDeleteTree              = "CanDsDeleteTree"
	EdgeKindCanDsListObject              = "CanDsListObject"
	EdgeKindCanDsControlAccess           = "CanDsControlAccess"
)

// Share-level permission edge kinds - Standard rights
const (
	EdgeKindCanDelete      = "CanDelete"
	EdgeKindCanReadControl = "CanReadControl"
	EdgeKindCanWriteDacl   = "CanWriteDacl"
	EdgeKindCanWriteOwner  = "CanWriteOwner"
)

// NTFS-level permission edge kinds
const (
	EdgeKindCanNTFSGenericRead          = "CanNTFSGenericRead"
	EdgeKindCanNTFSGenericWrite         = "CanNTFSGenericWrite"
	EdgeKindCanNTFSGenericExecute       = "CanNTFSGenericExecute"
	EdgeKindCanNTFSGenericAll           = "CanNTFSGenericAll"
	EdgeKindCanNTFSMaximumAllowed       = "CanNTFSMaximumAllowed"
	EdgeKindCanNTFSAccessSystemSecurity = "CanNTFSAccessSystemSecurity"
	EdgeKindCanNTFSSynchronize          = "CanNTFSSynchronize"
	EdgeKindCanNTFSWriteOwner           = "CanNTFSWriteOwner"
	EdgeKindCanNTFSWriteDacl            = "CanNTFSWriteDacl"
	EdgeKindCanNTFSReadControl          = "CanNTFSReadControl"
	EdgeKindCanNTFSDelete               = "CanNTFSDelete"
)

// AllNodeKinds returns all node kinds
func AllNodeKinds() []string {
	return []string{
		NodeKindNetworkShareBase,
		NodeKindNetworkShareHost,
		NodeKindNetworkShareDFS,
		NodeKindNetworkShareSMB,
		NodeKindFile,
		NodeKindDirectory,
		NodeKindPrincipal,
		NodeKindUser,
		NodeKindGroup,
	}
}

// AllEdgeKinds returns all edge kinds
func AllEdgeKinds() []string {
	return []string{
		// Containment
		EdgeKindHasNetworkShare,
		EdgeKindHostsNetworkShare,
		EdgeKindContains,
		// Share-level generic
		EdgeKindCanGenericExecute,
		EdgeKindCanGenericWrite,
		EdgeKindCanGenericRead,
		EdgeKindCanGenericAll,
		// Share-level DS
		EdgeKindCanDsCreateChild,
		EdgeKindCanDsDeleteChild,
		EdgeKindCanDsListContents,
		EdgeKindCanDsWriteExtendedProperties,
		EdgeKindCanDsReadProperty,
		EdgeKindCanDsWriteProperty,
		EdgeKindCanDsDeleteTree,
		EdgeKindCanDsListObject,
		EdgeKindCanDsControlAccess,
		// Share-level standard
		EdgeKindCanDelete,
		EdgeKindCanReadControl,
		EdgeKindCanWriteDacl,
		EdgeKindCanWriteOwner,
		// NTFS-level
		EdgeKindCanNTFSGenericRead,
		EdgeKindCanNTFSGenericWrite,
		EdgeKindCanNTFSGenericExecute,
		EdgeKindCanNTFSGenericAll,
		EdgeKindCanNTFSMaximumAllowed,
		EdgeKindCanNTFSAccessSystemSecurity,
		EdgeKindCanNTFSSynchronize,
		EdgeKindCanNTFSWriteOwner,
		EdgeKindCanNTFSWriteDacl,
		EdgeKindCanNTFSReadControl,
		EdgeKindCanNTFSDelete,
	}
}
