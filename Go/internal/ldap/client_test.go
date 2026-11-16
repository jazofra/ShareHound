package ldap

import "testing"

func TestComputerCandidateBetterThan(t *testing.T) {
	stale := computerCandidate{sid: "stale", samMatches: true, enabled: false, lastLogon: 100}
	live := computerCandidate{sid: "live", samMatches: true, enabled: true, lastLogon: 50}
	newer := computerCandidate{sid: "newer", samMatches: true, enabled: true, lastLogon: 80}
	other := computerCandidate{sid: "other", samMatches: false, enabled: true, lastLogon: 999}

	if !live.betterThan(stale) || stale.betterThan(live) {
		t.Error("enabled account should beat disabled one")
	}
	if !newer.betterThan(live) || live.betterThan(newer) {
		t.Error("most recent logon should win among enabled accounts")
	}
	if !stale.betterThan(other) || other.betterThan(stale) {
		t.Error("matching sAMAccountName should win first")
	}
}
