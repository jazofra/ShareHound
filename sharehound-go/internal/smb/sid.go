// Package smb provides SMB session management and security descriptor parsing.
package smb

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SID represents a Windows Security Identifier.
type SID struct {
	Revision            uint8
	SubAuthorityCount   uint8
	IdentifierAuthority [6]byte
	SubAuthorities      []uint32
}

// ParseSID parses a binary SID into a SID structure.
func ParseSID(data []byte) (*SID, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("SID data too short: %d bytes", len(data))
	}

	sid := &SID{
		Revision:          data[0],
		SubAuthorityCount: data[1],
	}

	copy(sid.IdentifierAuthority[:], data[2:8])

	expectedLen := 8 + int(sid.SubAuthorityCount)*4
	if len(data) < expectedLen {
		return nil, fmt.Errorf("SID data too short for %d sub-authorities", sid.SubAuthorityCount)
	}

	sid.SubAuthorities = make([]uint32, sid.SubAuthorityCount)
	for i := 0; i < int(sid.SubAuthorityCount); i++ {
		offset := 8 + i*4
		sid.SubAuthorities[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
	}

	return sid, nil
}

// String returns the canonical string representation of the SID.
// Format: S-R-I-S1-S2-...-Sn
func (s *SID) String() string {
	if s == nil {
		return ""
	}

	// Calculate identifier authority value
	var identAuth uint64
	for i := 0; i < 6; i++ {
		identAuth = (identAuth << 8) | uint64(s.IdentifierAuthority[i])
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("S-%d-%d", s.Revision, identAuth))

	for _, sa := range s.SubAuthorities {
		sb.WriteString(fmt.Sprintf("-%d", sa))
	}

	return sb.String()
}

// Size returns the size of the SID in bytes.
func (s *SID) Size() int {
	return 8 + int(s.SubAuthorityCount)*4
}

// IsWellKnown checks if this is a well-known SID.
func (s *SID) IsWellKnown() bool {
	str := s.String()
	return strings.HasPrefix(str, "S-1-5-32-") || // BUILTIN
		str == "S-1-5-18" || // LOCAL SYSTEM
		str == "S-1-5-19" || // LOCAL SERVICE
		str == "S-1-5-20" // NETWORK SERVICE
}

// WellKnownSIDs maps well-known SIDs to their names.
var WellKnownSIDs = map[string]string{
	"S-1-0-0":      "Null SID",
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "Local",
	"S-1-2-1":      "Console Logon",
	"S-1-3-0":      "Creator Owner",
	"S-1-3-1":      "Creator Group",
	"S-1-5-1":      "Dialup",
	"S-1-5-2":      "Network",
	"S-1-5-3":      "Batch",
	"S-1-5-4":      "Interactive",
	"S-1-5-6":      "Service",
	"S-1-5-7":      "Anonymous",
	"S-1-5-9":      "Enterprise Domain Controllers",
	"S-1-5-10":     "Principal Self",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-12":     "Restricted Code",
	"S-1-5-13":     "Terminal Server Users",
	"S-1-5-14":     "Remote Interactive Logon",
	"S-1-5-18":     "Local System",
	"S-1-5-19":     "NT Authority\\Local Service",
	"S-1-5-20":     "NT Authority\\Network Service",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-32-547": "BUILTIN\\Power Users",
	"S-1-5-32-548": "BUILTIN\\Account Operators",
	"S-1-5-32-549": "BUILTIN\\Server Operators",
	"S-1-5-32-550": "BUILTIN\\Print Operators",
	"S-1-5-32-551": "BUILTIN\\Backup Operators",
	"S-1-5-32-552": "BUILTIN\\Replicators",
}

// GetWellKnownName returns the name for a well-known SID, or empty string if not known.
func GetWellKnownName(sidString string) string {
	return WellKnownSIDs[sidString]
}

// IsDomainSID returns true if the SID is a domain-relative SID (S-1-5-21-*).
// Domain SIDs already contain the domain identifier and do not need a domain prefix
// for BloodHound matching. Non-domain SIDs (well-known / BUILTIN) need to be
// prefixed with "DOMAIN.FQDN-" so BloodHound can resolve them.
func IsDomainSID(sidString string) bool {
	return strings.HasPrefix(sidString, "S-1-5-21-")
}

// IsEveryone returns true if this is the Everyone SID (S-1-1-0).
func (s *SID) IsEveryone() bool {
	return s.String() == "S-1-1-0"
}

// IsBuiltinAdministrators returns true if this is the Administrators SID (S-1-5-32-544).
func (s *SID) IsBuiltinAdministrators() bool {
	return s.String() == "S-1-5-32-544"
}

// IsLocalSystem returns true if this is the Local System SID (S-1-5-18).
func (s *SID) IsLocalSystem() bool {
	return s.String() == "S-1-5-18"
}
