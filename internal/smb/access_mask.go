// Package smb provides SMB session management and security descriptor parsing.
package smb

import "github.com/specterops/sharehound/pkg/kinds"

// Share-level access mask flags
const (
	// Directory Service rights
	DS_CREATE_CHILD            uint32 = 0x00000001
	DS_DELETE_CHILD            uint32 = 0x00000002
	DS_LIST_CONTENTS           uint32 = 0x00000004
	DS_WRITE_PROPERTY_EXTENDED uint32 = 0x00000008
	DS_READ_PROPERTY           uint32 = 0x00000010
	DS_WRITE_PROPERTY          uint32 = 0x00000020
	DS_DELETE_TREE             uint32 = 0x00000040
	DS_LIST_OBJECT             uint32 = 0x00000080
	DS_CONTROL_ACCESS          uint32 = 0x00000100

	// Standard rights
	ACCESS_DELETE       uint32 = 0x00010000
	ACCESS_READ_CONTROL uint32 = 0x00020000
	ACCESS_WRITE_DAC    uint32 = 0x00040000
	ACCESS_WRITE_OWNER  uint32 = 0x00080000

	// Generic rights
	GENERIC_ALL     uint32 = 0x10000000
	GENERIC_EXECUTE uint32 = 0x20000000
	GENERIC_WRITE   uint32 = 0x40000000
	GENERIC_READ    uint32 = 0x80000000
)

// NTFS-level access mask flags
const (
	NTFS_GENERIC_READ           uint32 = 0x80000000
	NTFS_GENERIC_WRITE          uint32 = 0x40000000
	NTFS_GENERIC_EXECUTE        uint32 = 0x20000000
	NTFS_GENERIC_ALL            uint32 = 0x10000000
	NTFS_MAXIMUM_ALLOWED        uint32 = 0x02000000
	NTFS_ACCESS_SYSTEM_SECURITY uint32 = 0x01000000
	NTFS_SYNCHRONIZE            uint32 = 0x00100000
	NTFS_WRITE_OWNER            uint32 = 0x00080000
	NTFS_WRITE_DACL             uint32 = 0x00040000
	NTFS_READ_CONTROL           uint32 = 0x00020000
	NTFS_DELETE                 uint32 = 0x00010000
)

// ShareRightsMapping maps edge kinds to share-level access mask flags.
var ShareRightsMapping = map[string]uint32{
	kinds.EdgeKindCanDsCreateChild:             DS_CREATE_CHILD,
	kinds.EdgeKindCanDsDeleteChild:             DS_DELETE_CHILD,
	kinds.EdgeKindCanDsListContents:            DS_LIST_CONTENTS,
	kinds.EdgeKindCanDsWriteExtendedProperties: DS_WRITE_PROPERTY_EXTENDED,
	kinds.EdgeKindCanDsReadProperty:            DS_READ_PROPERTY,
	kinds.EdgeKindCanDsWriteProperty:           DS_WRITE_PROPERTY,
	kinds.EdgeKindCanDsDeleteTree:              DS_DELETE_TREE,
	kinds.EdgeKindCanDsListObject:              DS_LIST_OBJECT,
	kinds.EdgeKindCanDsControlAccess:           DS_CONTROL_ACCESS,
	kinds.EdgeKindCanDelete:                    ACCESS_DELETE,
	kinds.EdgeKindCanReadControl:               ACCESS_READ_CONTROL,
	kinds.EdgeKindCanWriteDacl:                 ACCESS_WRITE_DAC,
	kinds.EdgeKindCanWriteOwner:                ACCESS_WRITE_OWNER,
	kinds.EdgeKindCanGenericAll:                GENERIC_ALL,
	kinds.EdgeKindCanGenericExecute:            GENERIC_EXECUTE,
	kinds.EdgeKindCanGenericWrite:              GENERIC_WRITE,
	kinds.EdgeKindCanGenericRead:               GENERIC_READ,
}

// NTFSRightsMapping maps edge kinds to NTFS-level access mask flags.
var NTFSRightsMapping = map[string]uint32{
	kinds.EdgeKindCanNTFSGenericRead:          NTFS_GENERIC_READ,
	kinds.EdgeKindCanNTFSGenericWrite:         NTFS_GENERIC_WRITE,
	kinds.EdgeKindCanNTFSGenericExecute:       NTFS_GENERIC_EXECUTE,
	kinds.EdgeKindCanNTFSGenericAll:           NTFS_GENERIC_ALL,
	kinds.EdgeKindCanNTFSMaximumAllowed:       NTFS_MAXIMUM_ALLOWED,
	kinds.EdgeKindCanNTFSAccessSystemSecurity: NTFS_ACCESS_SYSTEM_SECURITY,
	kinds.EdgeKindCanNTFSSynchronize:          NTFS_SYNCHRONIZE,
	kinds.EdgeKindCanNTFSWriteOwner:           NTFS_WRITE_OWNER,
	kinds.EdgeKindCanNTFSWriteDacl:            NTFS_WRITE_DACL,
	kinds.EdgeKindCanNTFSReadControl:          NTFS_READ_CONTROL,
	kinds.EdgeKindCanNTFSDelete:               NTFS_DELETE,
}

// GetShareRightsForMask returns the edge kinds for a given access mask using share-level mapping.
func GetShareRightsForMask(mask uint32) []string {
	var rights []string
	for edgeKind, flag := range ShareRightsMapping {
		if mask&flag != 0 {
			rights = append(rights, edgeKind)
		}
	}
	return rights
}

// GetNTFSRightsForMask returns the edge kinds for a given access mask using NTFS-level mapping.
func GetNTFSRightsForMask(mask uint32) []string {
	var rights []string
	for edgeKind, flag := range NTFSRightsMapping {
		if mask&flag != 0 {
			rights = append(rights, edgeKind)
		}
	}
	return rights
}

// hasAny returns true if edgeKinds contains any of the targets.
func hasAny(edgeKinds []string, targets ...string) bool {
	for _, k := range edgeKinds {
		for _, t := range targets {
			if k == t {
				return true
			}
		}
	}
	return false
}

// ComputeEffectiveRights returns the effective access edge kinds for a single SID
// by intersecting its share-level generic rights with its NTFS-level generic rights.
//
// Windows enforces both layers when a file is accessed over SMB: the share DACL is
// checked first, then the NTFS DACL.  A principal needs permission at both layers to
// perform an operation, so effective access = shareRights ∩ ntfsRights.
//
// Only the four generic right categories (Read / Write / Execute / All) are considered
// because the DS_* share rights have no direct NTFS counterpart.
//
// Note: this is per-SID only.  Group memberships are not resolved here — a user who
// inherits share read through a group and has NTFS read directly will not receive an
// effective edge unless both ACEs reference the same SID.
func ComputeEffectiveRights(shareKinds, ntfsKinds []string) []string {
	readShare  := hasAny(shareKinds, kinds.EdgeKindCanGenericRead, kinds.EdgeKindCanGenericAll)
	writeShare := hasAny(shareKinds, kinds.EdgeKindCanGenericWrite, kinds.EdgeKindCanGenericAll)
	execShare  := hasAny(shareKinds, kinds.EdgeKindCanGenericExecute, kinds.EdgeKindCanGenericAll)

	readNTFS  := hasAny(ntfsKinds, kinds.EdgeKindCanNTFSGenericRead, kinds.EdgeKindCanNTFSGenericAll)
	writeNTFS := hasAny(ntfsKinds, kinds.EdgeKindCanNTFSGenericWrite, kinds.EdgeKindCanNTFSGenericAll)
	execNTFS  := hasAny(ntfsKinds, kinds.EdgeKindCanNTFSGenericExecute, kinds.EdgeKindCanNTFSGenericAll)

	var effective []string
	if readShare && readNTFS {
		effective = append(effective, kinds.EdgeKindCanEffectiveRead)
	}
	if writeShare && writeNTFS {
		effective = append(effective, kinds.EdgeKindCanEffectiveWrite)
	}
	if execShare && execNTFS {
		effective = append(effective, kinds.EdgeKindCanEffectiveExecute)
	}
	return effective
}
