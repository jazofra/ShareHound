// Package utils provides utility functions for ShareHound.
package utils

// Share type constants from lmshare.h
const (
	STYPE_DISKTREE  = 0x0        // Disk drive
	STYPE_PRINTQ    = 0x1        // Print queue
	STYPE_DEVICE    = 0x2        // Communication device
	STYPE_IPC       = 0x3        // Interprocess communication (IPC)
	STYPE_SPECIAL   = 0x80000000 // Administrative share (IPC$, ADMIN$, C$, etc.)
	STYPE_TEMPORARY = 0x40000000 // Temporary share
)

// Share type names
const (
	STYPE_NAME_DISKTREE  = "STYPE_DISKTREE"
	STYPE_NAME_PRINTQ    = "STYPE_PRINTQ"
	STYPE_NAME_DEVICE    = "STYPE_DEVICE"
	STYPE_NAME_IPC       = "STYPE_IPC"
	STYPE_NAME_SPECIAL   = "STYPE_SPECIAL"
	STYPE_NAME_TEMPORARY = "STYPE_TEMPORARY"
)

// STYPEMask extracts share type flags from a share type value.
// Returns a list of flag names that are set.
func STYPEMask(stypeValue uint32) []string {
	var flags []string

	// Check base type (lower 2 bits)
	baseType := stypeValue & 0b11
	switch baseType {
	case STYPE_DISKTREE:
		flags = append(flags, STYPE_NAME_DISKTREE)
	case STYPE_PRINTQ:
		flags = append(flags, STYPE_NAME_PRINTQ)
	case STYPE_DEVICE:
		flags = append(flags, STYPE_NAME_DEVICE)
	case STYPE_IPC:
		flags = append(flags, STYPE_NAME_IPC)
	}

	// Check additional flags
	if stypeValue&STYPE_SPECIAL == STYPE_SPECIAL {
		flags = append(flags, STYPE_NAME_SPECIAL)
	}
	if stypeValue&STYPE_TEMPORARY == STYPE_TEMPORARY {
		flags = append(flags, STYPE_NAME_TEMPORARY)
	}

	return flags
}

// IsDiskShare returns true if the share type indicates a disk share.
func IsDiskShare(stypeValue uint32) bool {
	return (stypeValue & 0b11) == STYPE_DISKTREE
}

// IsSpecialShare returns true if the share is a special/administrative share.
func IsSpecialShare(stypeValue uint32) bool {
	return stypeValue&STYPE_SPECIAL == STYPE_SPECIAL
}

// IsIPCShare returns true if the share is an IPC share.
func IsIPCShare(stypeValue uint32) bool {
	return (stypeValue & 0b11) == STYPE_IPC
}
