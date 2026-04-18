// Package smb provides SMB session management and security descriptor parsing.
package smb

// SMB2 Info Types
const (
	SMB2_0_INFO_FILE       uint8 = 0x01
	SMB2_0_INFO_FILESYSTEM uint8 = 0x02
	SMB2_0_INFO_SECURITY   uint8 = 0x03
	SMB2_0_INFO_QUOTA      uint8 = 0x04
)

// Security Information flags
const (
	OWNER_SECURITY_INFORMATION = 0x00000001
	GROUP_SECURITY_INFORMATION = 0x00000002
	DACL_SECURITY_INFORMATION  = 0x00000004
	SACL_SECURITY_INFORMATION  = 0x00000008
)
