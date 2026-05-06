package smb

import (
	"sort"
	"testing"

	"github.com/specterops/sharehound/pkg/kinds"
)

func TestGetShareRightsForMask_StandardReadPermission(t *testing.T) {
	// Windows "Read" share permission = 0x001200A9
	// FILE_READ_DATA(0x1) | FILE_READ_EA(0x8) | FILE_EXECUTE(0x20) |
	// FILE_READ_ATTRIBUTES(0x80) | READ_CONTROL(0x20000) | SYNCHRONIZE(0x100000)
	mask := uint32(0x001200A9)
	rights := GetShareRightsForMask(mask)

	rightSet := make(map[string]bool)
	for _, r := range rights {
		rightSet[r] = true
	}

	if !rightSet[kinds.EdgeKindCanShareRead] {
		t.Errorf("Expected CanShareRead for standard Read share permission (0x%08x), got: %v", mask, rights)
	}
	if !rightSet[kinds.EdgeKindCanShareExecute] {
		t.Errorf("Expected CanShareExecute for standard Read share permission (0x%08x), got: %v", mask, rights)
	}
	if !rightSet[kinds.EdgeKindCanReadControl] {
		t.Errorf("Expected CanReadControl for standard Read share permission (0x%08x), got: %v", mask, rights)
	}
	// Should NOT have generic read
	if rightSet[kinds.EdgeKindCanGenericRead] {
		t.Errorf("Did not expect CanGenericRead for standard Read share permission (0x%08x)", mask)
	}
}

func TestGetShareRightsForMask_StandardChangePermission(t *testing.T) {
	// Windows "Change" share permission = 0x001301BF
	mask := uint32(0x001301BF)
	rights := GetShareRightsForMask(mask)

	rightSet := make(map[string]bool)
	for _, r := range rights {
		rightSet[r] = true
	}

	if !rightSet[kinds.EdgeKindCanShareRead] {
		t.Errorf("Expected CanShareRead for Change permission, got: %v", rights)
	}
	if !rightSet[kinds.EdgeKindCanShareWrite] {
		t.Errorf("Expected CanShareWrite for Change permission, got: %v", rights)
	}
	if !rightSet[kinds.EdgeKindCanShareExecute] {
		t.Errorf("Expected CanShareExecute for Change permission, got: %v", rights)
	}
}

func TestGetShareRightsForMask_FullControl(t *testing.T) {
	// Windows "Full Control" share permission = 0x001F01FF
	mask := uint32(0x001F01FF)
	rights := GetShareRightsForMask(mask)

	rightSet := make(map[string]bool)
	for _, r := range rights {
		rightSet[r] = true
	}

	if !rightSet[kinds.EdgeKindCanShareRead] {
		t.Errorf("Expected CanShareRead for Full Control, got: %v", rights)
	}
	if !rightSet[kinds.EdgeKindCanShareWrite] {
		t.Errorf("Expected CanShareWrite for Full Control, got: %v", rights)
	}
	if !rightSet[kinds.EdgeKindCanShareExecute] {
		t.Errorf("Expected CanShareExecute for Full Control, got: %v", rights)
	}
	if !rightSet[kinds.EdgeKindCanDelete] {
		t.Errorf("Expected CanDelete for Full Control, got: %v", rights)
	}
}

func TestGetShareRightsForMask_GenericRead(t *testing.T) {
	// Generic read flag (rare in practice but should still work)
	mask := uint32(0x80000000)
	rights := GetShareRightsForMask(mask)

	rightSet := make(map[string]bool)
	for _, r := range rights {
		rightSet[r] = true
	}

	if !rightSet[kinds.EdgeKindCanGenericRead] {
		t.Errorf("Expected CanGenericRead for GENERIC_READ flag, got: %v", rights)
	}
}

func TestComputeEffectiveRights_SpecificShareRead_NTFSReadData(t *testing.T) {
	// The primary bug scenario: share grants specific FILE_READ_DATA (CanShareRead),
	// NTFS grants CanNTFSReadData → should produce CanEffectiveRead.
	shareKinds := []string{kinds.EdgeKindCanShareRead, kinds.EdgeKindCanShareExecute, kinds.EdgeKindCanReadControl}
	ntfsKinds := []string{kinds.EdgeKindCanNTFSReadData, kinds.EdgeKindCanNTFSReadAttributes}

	effective := ComputeEffectiveRights(shareKinds, ntfsKinds)

	effectiveSet := make(map[string]bool)
	for _, e := range effective {
		effectiveSet[e] = true
	}

	if !effectiveSet[kinds.EdgeKindCanEffectiveRead] {
		t.Errorf("Expected CanEffectiveRead when share has CanShareRead and NTFS has CanNTFSReadData, got: %v", effective)
	}
}

func TestComputeEffectiveRights_GenericShareRead_NTFSReadData(t *testing.T) {
	// Legacy scenario: share has GENERIC_READ, NTFS has specific read.
	shareKinds := []string{kinds.EdgeKindCanGenericRead}
	ntfsKinds := []string{kinds.EdgeKindCanNTFSReadData}

	effective := ComputeEffectiveRights(shareKinds, ntfsKinds)

	effectiveSet := make(map[string]bool)
	for _, e := range effective {
		effectiveSet[e] = true
	}

	if !effectiveSet[kinds.EdgeKindCanEffectiveRead] {
		t.Errorf("Expected CanEffectiveRead when share has CanGenericRead and NTFS has CanNTFSReadData, got: %v", effective)
	}
}

func TestComputeEffectiveRights_NoShareRead_NTFSReadData(t *testing.T) {
	// No share read permission → no effective read even with NTFS read.
	shareKinds := []string{kinds.EdgeKindCanShareExecute}
	ntfsKinds := []string{kinds.EdgeKindCanNTFSReadData}

	effective := ComputeEffectiveRights(shareKinds, ntfsKinds)

	for _, e := range effective {
		if e == kinds.EdgeKindCanEffectiveRead {
			t.Errorf("Did not expect CanEffectiveRead when share lacks read permission, got: %v", effective)
		}
	}
}

func TestComputeEffectiveRights_ChangePermission_FullEffective(t *testing.T) {
	// Share "Change" permission → should produce read, write, and execute effective edges
	// when NTFS also grants all three.
	shareKinds := []string{kinds.EdgeKindCanShareRead, kinds.EdgeKindCanShareWrite, kinds.EdgeKindCanShareExecute}
	ntfsKinds := []string{kinds.EdgeKindCanNTFSReadData, kinds.EdgeKindCanNTFSWriteData, kinds.EdgeKindCanNTFSExecute}

	effective := ComputeEffectiveRights(shareKinds, ntfsKinds)
	sort.Strings(effective)

	expected := []string{kinds.EdgeKindCanEffectiveExecute, kinds.EdgeKindCanEffectiveRead, kinds.EdgeKindCanEffectiveWrite}
	sort.Strings(expected)

	if len(effective) != len(expected) {
		t.Fatalf("Expected %v, got %v", expected, effective)
	}
	for i := range expected {
		if effective[i] != expected[i] {
			t.Errorf("Expected %v, got %v", expected, effective)
			break
		}
	}
}

func TestComputeEffectiveRights_GenericAll_CoversAll(t *testing.T) {
	// GENERIC_ALL at share level should satisfy read, write, and execute.
	shareKinds := []string{kinds.EdgeKindCanGenericAll}
	ntfsKinds := []string{kinds.EdgeKindCanNTFSReadData, kinds.EdgeKindCanNTFSWriteData, kinds.EdgeKindCanNTFSExecute}

	effective := ComputeEffectiveRights(shareKinds, ntfsKinds)

	effectiveSet := make(map[string]bool)
	for _, e := range effective {
		effectiveSet[e] = true
	}

	if !effectiveSet[kinds.EdgeKindCanEffectiveRead] {
		t.Error("Expected CanEffectiveRead with GenericAll share")
	}
	if !effectiveSet[kinds.EdgeKindCanEffectiveWrite] {
		t.Error("Expected CanEffectiveWrite with GenericAll share")
	}
	if !effectiveSet[kinds.EdgeKindCanEffectiveExecute] {
		t.Error("Expected CanEffectiveExecute with GenericAll share")
	}
}
