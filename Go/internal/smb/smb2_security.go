// Package smb provides SMB session management and security descriptor parsing.
package smb

import (
	"github.com/medianexapp/go-smb2"
)

// Security information request flags
const (
	SecurityInfoOwner smb2.SecurityInformationRequestFlags = 0x00000001
	SecurityInfoGroup smb2.SecurityInformationRequestFlags = 0x00000002
	SecurityInfoDACL  smb2.SecurityInformationRequestFlags = 0x00000004
	SecurityInfoSACL  smb2.SecurityInformationRequestFlags = 0x00000008
)

// QuerySecurityDescriptorLinked queries the security descriptor for a file or directory
// using the medianexapp/go-smb2 fork which has native security descriptor support.
// Returns nil, nil if the security descriptor cannot be retrieved (e.g., access denied).
func QuerySecurityDescriptorLinked(share *smb2.Share, path string) ([]byte, error) {
	if share == nil {
		return nil, nil
	}

	// Use the native SecurityInfoRaw method from the medianexapp fork
	// This queries OWNER | GROUP | DACL information
	flags := SecurityInfoOwner | SecurityInfoGroup | SecurityInfoDACL

	sdBytes, err := share.SecurityInfoRaw(path, flags)
	if err != nil {
		// Return nil for access denied or other errors - this is expected for some files
		// The caller can still list and traverse directories even without READ_CONTROL permission
		return nil, nil
	}

	return sdBytes, nil
}
