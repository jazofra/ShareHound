// Package smb provides SMB session management and security descriptor parsing.
package smb

import (
	"encoding/binary"
	"fmt"
)

// Security descriptor control flags
const (
	SE_OWNER_DEFAULTED       = 0x0001
	SE_GROUP_DEFAULTED       = 0x0002
	SE_DACL_PRESENT          = 0x0004
	SE_DACL_DEFAULTED        = 0x0008
	SE_SACL_PRESENT          = 0x0010
	SE_SACL_DEFAULTED        = 0x0020
	SE_DACL_AUTO_INHERIT_REQ = 0x0100
	SE_SACL_AUTO_INHERIT_REQ = 0x0200
	SE_DACL_AUTO_INHERITED   = 0x0400
	SE_SACL_AUTO_INHERITED   = 0x0800
	SE_DACL_PROTECTED        = 0x1000
	SE_SACL_PROTECTED        = 0x2000
	SE_RM_CONTROL_VALID      = 0x4000
	SE_SELF_RELATIVE         = 0x8000
)

// ACE type constants
const (
	ACCESS_ALLOWED_ACE_TYPE                 = 0x00
	ACCESS_DENIED_ACE_TYPE                  = 0x01
	SYSTEM_AUDIT_ACE_TYPE                   = 0x02
	SYSTEM_ALARM_ACE_TYPE                   = 0x03
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE        = 0x04
	ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE           = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE            = 0x07
	SYSTEM_ALARM_OBJECT_ACE_TYPE            = 0x08
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE         = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0x0C
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE          = 0x0D
	SYSTEM_ALARM_CALLBACK_ACE_TYPE          = 0x0E
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   = 0x0F
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   = 0x10
	SYSTEM_MANDATORY_LABEL_ACE_TYPE         = 0x11
)

// ACE flag constants
const (
	OBJECT_INHERIT_ACE         = 0x01
	CONTAINER_INHERIT_ACE      = 0x02
	NO_PROPAGATE_INHERIT_ACE   = 0x04
	INHERIT_ONLY_ACE           = 0x08
	INHERITED_ACE              = 0x10
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
	FAILED_ACCESS_ACE_FLAG     = 0x80
)

// SecurityDescriptor represents a Windows security descriptor.
type SecurityDescriptor struct {
	Revision uint8
	Sbz1     uint8
	Control  uint16
	OwnerSID *SID
	GroupSID *SID
	Sacl     *ACL
	Dacl     *ACL
}

// ACL represents an Access Control List.
type ACL struct {
	AclRevision uint8
	Sbz1        uint8
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
	Aces        []ACE
}

// ACE represents an Access Control Entry.
type ACE struct {
	AceType  uint8
	AceFlags uint8
	AceSize  uint16
	Mask     uint32
	SID      *SID
}

// ParseSecurityDescriptor parses a binary security descriptor.
func ParseSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("security descriptor too short: %d bytes", len(data))
	}

	sd := &SecurityDescriptor{
		Revision: data[0],
		Sbz1:     data[1],
		Control:  binary.LittleEndian.Uint16(data[2:4]),
	}

	offsetOwner := binary.LittleEndian.Uint32(data[4:8])
	offsetGroup := binary.LittleEndian.Uint32(data[8:12])
	offsetSacl := binary.LittleEndian.Uint32(data[12:16])
	offsetDacl := binary.LittleEndian.Uint32(data[16:20])

	// Parse Owner SID
	if offsetOwner > 0 && int(offsetOwner) < len(data) {
		sid, err := ParseSID(data[offsetOwner:])
		if err == nil {
			sd.OwnerSID = sid
		}
	}

	// Parse Group SID
	if offsetGroup > 0 && int(offsetGroup) < len(data) {
		sid, err := ParseSID(data[offsetGroup:])
		if err == nil {
			sd.GroupSID = sid
		}
	}

	// Parse SACL (System ACL) - usually not needed but parse for completeness
	if offsetSacl > 0 && (sd.Control&SE_SACL_PRESENT) != 0 && int(offsetSacl) < len(data) {
		acl, err := ParseACL(data[offsetSacl:])
		if err == nil {
			sd.Sacl = acl
		}
	}

	// Parse DACL (Discretionary ACL) - this is what we mainly care about
	if offsetDacl > 0 && (sd.Control&SE_DACL_PRESENT) != 0 && int(offsetDacl) < len(data) {
		acl, err := ParseACL(data[offsetDacl:])
		if err == nil {
			sd.Dacl = acl
		}
	}

	return sd, nil
}

// ParseACL parses a binary ACL.
func ParseACL(data []byte) (*ACL, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ACL too short: %d bytes", len(data))
	}

	acl := &ACL{
		AclRevision: data[0],
		Sbz1:        data[1],
		AclSize:     binary.LittleEndian.Uint16(data[2:4]),
		AceCount:    binary.LittleEndian.Uint16(data[4:6]),
		Sbz2:        binary.LittleEndian.Uint16(data[6:8]),
	}

	// Parse ACEs
	offset := 8
	for i := 0; i < int(acl.AceCount) && offset < len(data); i++ {
		ace, size, err := ParseACE(data[offset:])
		if err != nil {
			break
		}
		acl.Aces = append(acl.Aces, *ace)
		offset += size
	}

	return acl, nil
}

// ParseACE parses a binary ACE and returns the ACE and its size.
func ParseACE(data []byte) (*ACE, int, error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("ACE header too short")
	}

	ace := &ACE{
		AceType:  data[0],
		AceFlags: data[1],
		AceSize:  binary.LittleEndian.Uint16(data[2:4]),
	}

	if len(data) < int(ace.AceSize) {
		return nil, 0, fmt.Errorf("ACE data too short")
	}

	// For standard ACE types, parse the mask and SID
	switch ace.AceType {
	case ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
		SYSTEM_AUDIT_ACE_TYPE, SYSTEM_ALARM_ACE_TYPE:
		if len(data) < 8 {
			return nil, 0, fmt.Errorf("ACE too short for mask")
		}
		ace.Mask = binary.LittleEndian.Uint32(data[4:8])

		// Parse SID starting at offset 8
		if len(data) > 8 {
			sid, err := ParseSID(data[8:])
			if err == nil {
				ace.SID = sid
			}
		}
	}

	return ace, int(ace.AceSize), nil
}

// IsAccessAllowed returns true if this is an ACCESS_ALLOWED ACE.
func (a *ACE) IsAccessAllowed() bool {
	return a.AceType == ACCESS_ALLOWED_ACE_TYPE
}

// IsAccessDenied returns true if this is an ACCESS_DENIED ACE.
func (a *ACE) IsAccessDenied() bool {
	return a.AceType == ACCESS_DENIED_ACE_TYPE
}

// HasMask checks if the ACE mask contains the specified flag.
func (a *ACE) HasMask(flag uint32) bool {
	return (a.Mask & flag) != 0
}

// AceTypeName returns the name of the ACE type.
func (a *ACE) AceTypeName() string {
	switch a.AceType {
	case ACCESS_ALLOWED_ACE_TYPE:
		return "ACCESS_ALLOWED"
	case ACCESS_DENIED_ACE_TYPE:
		return "ACCESS_DENIED"
	case SYSTEM_AUDIT_ACE_TYPE:
		return "SYSTEM_AUDIT"
	case SYSTEM_ALARM_ACE_TYPE:
		return "SYSTEM_ALARM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", a.AceType)
	}
}
