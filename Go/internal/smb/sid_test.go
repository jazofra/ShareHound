package smb

import (
	"testing"
)

func TestParseSID(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
		wantErr  bool
	}{
		{
			name: "Everyone (S-1-1-0)",
			data: []byte{
				0x01,                   // Revision
				0x01,                   // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IdentifierAuthority (1)
				0x00, 0x00, 0x00, 0x00, // SubAuthority[0] (0)
			},
			expected: "S-1-1-0",
			wantErr:  false,
		},
		{
			name: "Administrators (S-1-5-32-544)",
			data: []byte{
				0x01,                   // Revision
				0x02,                   // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (5)
				0x20, 0x00, 0x00, 0x00, // SubAuthority[0] (32)
				0x20, 0x02, 0x00, 0x00, // SubAuthority[1] (544)
			},
			expected: "S-1-5-32-544",
			wantErr:  false,
		},
		{
			name: "Local System (S-1-5-18)",
			data: []byte{
				0x01,                   // Revision
				0x01,                   // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (5)
				0x12, 0x00, 0x00, 0x00, // SubAuthority[0] (18)
			},
			expected: "S-1-5-18",
			wantErr:  false,
		},
		{
			name: "Domain User (S-1-5-21-x-x-x-1001)",
			data: []byte{
				0x01,                   // Revision
				0x05,                   // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // IdentifierAuthority (5)
				0x15, 0x00, 0x00, 0x00, // SubAuthority[0] (21)
				0x01, 0x02, 0x03, 0x04, // SubAuthority[1]
				0x05, 0x06, 0x07, 0x08, // SubAuthority[2]
				0x09, 0x0a, 0x0b, 0x0c, // SubAuthority[3]
				0xe9, 0x03, 0x00, 0x00, // SubAuthority[4] (1001)
			},
			expected: "S-1-5-21-67305985-134678021-202050057-1001",
			wantErr:  false,
		},
		{
			name:     "Too short",
			data:     []byte{0x01, 0x01, 0x00, 0x00},
			expected: "",
			wantErr:  true,
		},
		{
			name: "Zero revision (edge case)",
			data: []byte{
				0x00,                   // Revision 0 (unusual but parseable)
				0x01,                   // SubAuthorityCount
				0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // IdentifierAuthority (1)
				0x00, 0x00, 0x00, 0x00, // SubAuthority[0] (0)
			},
			expected: "S-0-1-0",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid, err := ParseSID(tt.data)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if sid.String() != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, sid.String())
			}
		})
	}
}

func TestSIDIsWellKnown(t *testing.T) {
	// Everyone SID
	everyoneSID := &SID{
		Revision:            1,
		SubAuthorityCount:   1,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 1},
		SubAuthorities:        []uint32{0},
	}

	if !everyoneSID.IsEveryone() {
		t.Error("Expected S-1-1-0 to be Everyone")
	}

	// Administrators SID
	adminSID := &SID{
		Revision:            1,
		SubAuthorityCount:   2,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthorities:        []uint32{32, 544},
	}

	if !adminSID.IsBuiltinAdministrators() {
		t.Error("Expected S-1-5-32-544 to be Administrators")
	}

	// Local System SID
	systemSID := &SID{
		Revision:            1,
		SubAuthorityCount:   1,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthorities:        []uint32{18},
	}

	if !systemSID.IsLocalSystem() {
		t.Error("Expected S-1-5-18 to be Local System")
	}
}

func TestSIDSize(t *testing.T) {
	tests := []struct {
		name     string
		subCount uint8
		expected int
	}{
		{"No subauthorities", 0, 8},
		{"One subauthority", 1, 12},
		{"Two subauthorities", 2, 16},
		{"Five subauthorities", 5, 28},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid := &SID{
				Revision:            1,
				SubAuthorityCount:   tt.subCount,
				IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
				SubAuthorities:        make([]uint32, tt.subCount),
			}

			if sid.Size() != tt.expected {
				t.Errorf("Expected size %d, got %d", tt.expected, sid.Size())
			}
		})
	}
}
