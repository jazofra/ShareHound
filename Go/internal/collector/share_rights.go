// Package collector provides data collection functionality for ShareHound.
package collector

import (
	"github.com/specterops/sharehound/internal/graph"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/smb"
)

// CollectShareRights collects share-level rights for a share.
func CollectShareRights(
	smbSession *smb.SMBSession,
	shareName string,
	log logger.LoggerInterface,
) (graph.ShareRights, error) {
	rights := make(graph.ShareRights)

	log.Debug("[collect_share_rights] Retrieving security descriptor for share: " + shareName)

	// Try to get share security descriptor
	sdBytes, err := smbSession.GetShareSecurityDescriptor(shareName)
	usedFallback := false

	if err != nil || len(sdBytes) == 0 {
		// Try fallback: get root folder security descriptor
		log.Debug("[collect_share_rights] Share-level security descriptor unavailable, trying root folder fallback...")
		sdBytes, err = smbSession.GetShareRootSecurityDescriptor(shareName)
		if err != nil || len(sdBytes) == 0 {
			log.Warning("[collect_share_rights] Could not retrieve security descriptor for share: " + shareName)
			return rights, nil
		}
		usedFallback = true
		log.Debug("[collect_share_rights] Using root folder NTFS permissions as fallback")
	}

	_ = usedFallback

	// Parse security descriptor
	sd, err := smb.ParseSecurityDescriptor(sdBytes)
	if err != nil {
		log.Debug("[collect_share_rights] Failed to parse security descriptor: " + err.Error())
		return rights, err
	}

	// Check DACL
	if sd.Dacl == nil {
		log.Debug("[collect_share_rights] DACL is None for share: " + shareName)
		return rights, nil
	}

	if len(sd.Dacl.Aces) == 0 {
		log.Debug("[collect_share_rights] DACL is empty (no ACEs) for share: " + shareName)
		return rights, nil
	}

	log.Debug("[collect_share_rights] Processing " + string(rune(len(sd.Dacl.Aces)+'0')) + " ACE(s)")

	// Process each ACE
	for _, ace := range sd.Dacl.Aces {
		// Only process ACCESS_ALLOWED ACEs
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

		// Get rights for this mask
		edgeKinds := smb.GetShareRightsForMask(ace.Mask)
		if len(edgeKinds) > 0 {
			rights[sid] = append(rights[sid], edgeKinds...)
		}
	}

	return rights, nil
}
