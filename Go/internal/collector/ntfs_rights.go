// Package collector provides data collection functionality for ShareHound.
package collector

import (
	"github.com/specterops/sharehound/internal/graph"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/smb"
)

// CollectNTFSRights collects NTFS-level rights for a file or directory.
func CollectNTFSRights(
	smbSession *smb.SMBSession,
	ogc *graph.OpenGraphContext,
	filePath string,
	log logger.LoggerInterface,
) (graph.ShareRights, error) {
	rights := make(graph.ShareRights)

	// Get security descriptor for the file/directory
	sd, err := smbSession.GetFileSecurityDescriptor(filePath)
	if err != nil {
		log.Debug("[collect_ntfs_rights] Error getting security descriptor: " + err.Error())
		return rights, nil
	}

	if sd == nil {
		return rights, nil
	}

	// Check DACL
	if sd.Dacl == nil {
		return rights, nil
	}

	// Process each ACE — only ACCESS_ALLOWED ACEs grant rights
	for _, ace := range sd.Dacl.Aces {
		if !ace.IsAccessAllowed() {
			continue
		}

		if ace.SID == nil {
			continue
		}

		sid := ace.SID.String()
		if sid == "" {
			continue
		}

		// Get NTFS rights for this mask
		edgeKinds := smb.GetNTFSRightsForMask(ace.Mask)
		if len(edgeKinds) > 0 {
			rights[sid] = append(rights[sid], edgeKinds...)
		}
	}

	return rights, nil
}
