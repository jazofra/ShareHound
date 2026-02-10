package smb

import (
	"testing"
)

// Test security descriptor parsing with a known good self-relative SD
func TestParseSecurityDescriptor(t *testing.T) {
	// This is a minimal self-relative security descriptor with:
	// - Revision: 1
	// - Control: SE_SELF_RELATIVE | SE_DACL_PRESENT (0x8004)
	// - Owner SID: S-1-5-32-544 (Administrators)
	// - Group SID: S-1-5-32-544 (Administrators)
	// - DACL with one ACE allowing Everyone full access
	testSD := []byte{
		// Header (20 bytes)
		0x01,       // Revision
		0x00,       // Sbz1
		0x04, 0x80, // Control (SE_SELF_RELATIVE | SE_DACL_PRESENT)
		0x30, 0x00, 0x00, 0x00, // OwnerOffset (48)
		0x40, 0x00, 0x00, 0x00, // GroupOffset (64)
		0x00, 0x00, 0x00, 0x00, // SaclOffset (0 = none)
		0x14, 0x00, 0x00, 0x00, // DaclOffset (20)

		// DACL at offset 20 (28 bytes)
		0x02,       // Revision
		0x00,       // Sbz1
		0x1c, 0x00, // AclSize (28)
		0x01, 0x00, // AceCount (1)
		0x00, 0x00, // Sbz2

		// ACE 1: ACCESS_ALLOWED_ACE for Everyone (S-1-1-0)
		0x00,       // AceType (ACCESS_ALLOWED)
		0x00,       // AceFlags
		0x14, 0x00, // AceSize (20)
		0xff, 0x01, 0x1f, 0x00, // Mask (GENERIC_ALL equivalent)
		// SID: S-1-1-0 (Everyone)
		0x01,                   // Revision
		0x01,                   // SubAuthorityCount
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IdentifierAuthority (1)
		0x00, 0x00, 0x00, 0x00, // SubAuthority[0] (0)

		// Owner SID at offset 48: S-1-5-32-544 (16 bytes)
		0x01,                   // Revision
		0x02,                   // SubAuthorityCount
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (5)
		0x20, 0x00, 0x00, 0x00, // SubAuthority[0] (32)
		0x20, 0x02, 0x00, 0x00, // SubAuthority[1] (544)

		// Group SID at offset 64: S-1-5-32-544 (16 bytes)
		0x01,                   // Revision
		0x02,                   // SubAuthorityCount
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (5)
		0x20, 0x00, 0x00, 0x00, // SubAuthority[0] (32)
		0x20, 0x02, 0x00, 0x00, // SubAuthority[1] (544)
	}

	sd, err := ParseSecurityDescriptor(testSD)
	if err != nil {
		t.Fatalf("Failed to parse security descriptor: %v", err)
	}

	// Verify revision
	if sd.Revision != 1 {
		t.Errorf("Expected revision 1, got %d", sd.Revision)
	}

	// Verify control flags
	if sd.Control&0x8004 != 0x8004 {
		t.Errorf("Expected SE_SELF_RELATIVE | SE_DACL_PRESENT, got 0x%04x", sd.Control)
	}

	// Verify DACL exists
	if sd.Dacl == nil {
		t.Fatal("Expected DACL to be present")
	}

	// Verify ACE count
	if len(sd.Dacl.Aces) != 1 {
		t.Errorf("Expected 1 ACE, got %d", len(sd.Dacl.Aces))
	}

	// Verify ACE is ACCESS_ALLOWED
	if len(sd.Dacl.Aces) > 0 && !sd.Dacl.Aces[0].IsAccessAllowed() {
		t.Error("Expected ACCESS_ALLOWED ACE")
	}

	// Verify Owner SID
	if sd.OwnerSID == nil {
		t.Fatal("Expected owner SID to be present")
	}
	ownerSIDStr := sd.OwnerSID.String()
	if ownerSIDStr != "S-1-5-32-544" {
		t.Errorf("Expected owner SID S-1-5-32-544, got %s", ownerSIDStr)
	}
}

func TestParseSecurityDescriptorTooShort(t *testing.T) {
	// Test with data shorter than minimum SD header
	shortData := []byte{0x01, 0x00, 0x04, 0x80}

	_, err := ParseSecurityDescriptor(shortData)
	if err == nil {
		t.Error("Expected error for too short data")
	}
}

func TestParseSecurityDescriptorUnusualRevision(t *testing.T) {
	// Test with unusual revision - parser is lenient and accepts it
	unusualSD := []byte{
		0x05,       // Unusual revision (5)
		0x00,       // Sbz1
		0x04, 0x80, // Control
		0x00, 0x00, 0x00, 0x00, // OwnerOffset
		0x00, 0x00, 0x00, 0x00, // GroupOffset
		0x00, 0x00, 0x00, 0x00, // SaclOffset
		0x00, 0x00, 0x00, 0x00, // DaclOffset
	}

	sd, err := ParseSecurityDescriptor(unusualSD)
	if err != nil {
		t.Fatalf("Unexpected error parsing unusual revision SD: %v", err)
	}
	if sd.Revision != 5 {
		t.Errorf("Expected revision 5, got %d", sd.Revision)
	}
}

func TestParseSecurityDescriptorNoDACL(t *testing.T) {
	// Test SD without DACL
	sdNoDACL := []byte{
		0x01,       // Revision
		0x00,       // Sbz1
		0x00, 0x80, // Control (SE_SELF_RELATIVE only, no SE_DACL_PRESENT)
		0x00, 0x00, 0x00, 0x00, // OwnerOffset
		0x00, 0x00, 0x00, 0x00, // GroupOffset
		0x00, 0x00, 0x00, 0x00, // SaclOffset
		0x00, 0x00, 0x00, 0x00, // DaclOffset
	}

	sd, err := ParseSecurityDescriptor(sdNoDACL)
	if err != nil {
		t.Fatalf("Failed to parse SD without DACL: %v", err)
	}

	if sd.Dacl != nil {
		t.Error("Expected DACL to be nil")
	}
}
