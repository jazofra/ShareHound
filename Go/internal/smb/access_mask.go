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

	// File-specific rights at the share level.
	// Windows share permissions (Read/Change/Full Control) use these specific
	// bits rather than the GENERIC_* flags. For example, the standard "Read"
	// share permission uses mask 0x001200A9 which sets SHARE_FILE_READ_DATA
	// (0x1) but NOT GENERIC_READ (0x80000000).
	SHARE_FILE_READ_DATA uint32 = 0x00000001 // FILE_READ_DATA at share level
	SHARE_FILE_WRITE_DATA uint32 = 0x00000002 // FILE_WRITE_DATA at share level
	SHARE_FILE_EXECUTE    uint32 = 0x00000020 // FILE_EXECUTE at share level
)

// NTFS-level access mask flags
const (
	NTFS_GENERIC_READ           uint32 = 0x80000000
	NTFS_GENERIC_WRITE          uint32 = 0x40000000
	NTFS_GENERIC_EXECUTE        uint32 = 0x20000000
	NTFS_GENERIC_ALL            uint32 = 0x10000000
	NTFS_ACCESS_SYSTEM_SECURITY uint32 = 0x01000000
	NTFS_SYNCHRONIZE            uint32 = 0x00100000
	NTFS_WRITE_OWNER            uint32 = 0x00080000
	NTFS_WRITE_DACL             uint32 = 0x00040000
	NTFS_READ_CONTROL           uint32 = 0x00020000
	NTFS_DELETE                 uint32 = 0x00010000
)

// NTFS object-specific (file/directory) access mask flags
const (
	NTFS_FILE_READ_DATA        uint32 = 0x00000001 // FILE_READ_DATA / FILE_LIST_DIRECTORY
	NTFS_FILE_WRITE_DATA       uint32 = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	NTFS_FILE_APPEND_DATA      uint32 = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	NTFS_FILE_READ_EA          uint32 = 0x00000008 // FILE_READ_EA
	NTFS_FILE_WRITE_EA         uint32 = 0x00000010 // FILE_WRITE_EA
	NTFS_FILE_EXECUTE          uint32 = 0x00000020 // FILE_EXECUTE / FILE_TRAVERSE
	NTFS_FILE_DELETE_CHILD     uint32 = 0x00000040 // FILE_DELETE_CHILD
	NTFS_FILE_READ_ATTRIBUTES  uint32 = 0x00000080 // FILE_READ_ATTRIBUTES
	NTFS_FILE_WRITE_ATTRIBUTES uint32 = 0x00000100 // FILE_WRITE_ATTRIBUTES
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
	// File-specific share rights — these bits overlap with DS_* constants but
	// have different semantics for file shares.  Both edge kinds are emitted
	// when the bit is set so that ComputeEffectiveRights can detect the
	// standard Windows share permissions (Read/Change/Full Control).
	kinds.EdgeKindCanShareRead:                 SHARE_FILE_READ_DATA,
	kinds.EdgeKindCanShareWrite:                SHARE_FILE_WRITE_DATA,
	kinds.EdgeKindCanShareExecute:              SHARE_FILE_EXECUTE,
}

// NTFSRightsMapping maps edge kinds to NTFS-level access mask flags.
var NTFSRightsMapping = map[string]uint32{
	kinds.EdgeKindCanNTFSGenericRead:          NTFS_GENERIC_READ,
	kinds.EdgeKindCanNTFSGenericWrite:         NTFS_GENERIC_WRITE,
	kinds.EdgeKindCanNTFSGenericExecute:       NTFS_GENERIC_EXECUTE,
	kinds.EdgeKindCanNTFSGenericAll:           NTFS_GENERIC_ALL,
	kinds.EdgeKindCanNTFSAccessSystemSecurity: NTFS_ACCESS_SYSTEM_SECURITY,
	kinds.EdgeKindCanNTFSSynchronize:          NTFS_SYNCHRONIZE,
	kinds.EdgeKindCanNTFSWriteOwner:           NTFS_WRITE_OWNER,
	kinds.EdgeKindCanNTFSWriteDacl:            NTFS_WRITE_DACL,
	kinds.EdgeKindCanNTFSReadControl:          NTFS_READ_CONTROL,
	kinds.EdgeKindCanNTFSDelete:               NTFS_DELETE,
	// Object-specific (file/directory) rights
	kinds.EdgeKindCanNTFSReadData:        NTFS_FILE_READ_DATA,
	kinds.EdgeKindCanNTFSWriteData:       NTFS_FILE_WRITE_DATA,
	kinds.EdgeKindCanNTFSAppendData:      NTFS_FILE_APPEND_DATA,
	kinds.EdgeKindCanNTFSReadEA:          NTFS_FILE_READ_EA,
	kinds.EdgeKindCanNTFSWriteEA:         NTFS_FILE_WRITE_EA,
	kinds.EdgeKindCanNTFSExecute:         NTFS_FILE_EXECUTE,
	kinds.EdgeKindCanNTFSDeleteChild:     NTFS_FILE_DELETE_CHILD,
	kinds.EdgeKindCanNTFSReadAttributes:  NTFS_FILE_READ_ATTRIBUTES,
	kinds.EdgeKindCanNTFSWriteAttributes: NTFS_FILE_WRITE_ATTRIBUTES,
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
// Both generic rights (GENERIC_READ, etc.) and file-specific rights (FILE_READ_DATA,
// etc.) are checked at the share level, because Windows share permissions typically
// use specific rights rather than generic flags.  The DS_* share rights have no
// direct NTFS counterpart and are not considered.
//
// Note: this is per-SID only.  Group memberships are not resolved here — a user who
// inherits share read through a group and has NTFS read directly will not receive an
// effective edge unless both ACEs reference the same SID.
func ComputeEffectiveRights(shareKinds, ntfsKinds []string) []string {
	readShare  := hasAny(shareKinds, kinds.EdgeKindCanGenericRead, kinds.EdgeKindCanGenericAll, kinds.EdgeKindCanShareRead)
	writeShare := hasAny(shareKinds, kinds.EdgeKindCanGenericWrite, kinds.EdgeKindCanGenericAll, kinds.EdgeKindCanShareWrite)
	execShare  := hasAny(shareKinds, kinds.EdgeKindCanGenericExecute, kinds.EdgeKindCanGenericAll, kinds.EdgeKindCanShareExecute)

	readNTFS  := hasAny(ntfsKinds, kinds.EdgeKindCanNTFSGenericRead, kinds.EdgeKindCanNTFSGenericAll, kinds.EdgeKindCanNTFSReadData)
	writeNTFS := hasAny(ntfsKinds, kinds.EdgeKindCanNTFSGenericWrite, kinds.EdgeKindCanNTFSGenericAll, kinds.EdgeKindCanNTFSWriteData)
	execNTFS  := hasAny(ntfsKinds, kinds.EdgeKindCanNTFSGenericExecute, kinds.EdgeKindCanNTFSGenericAll, kinds.EdgeKindCanNTFSExecute)

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
