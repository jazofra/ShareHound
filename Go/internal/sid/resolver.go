// Package sid provides SID resolution functionality.
package sid

import (
	"sync"

	"github.com/specterops/sharehound/internal/smb"
)

// Resolver resolves SIDs to usernames.
type Resolver struct {
	smbSession *smb.SMBSession
	cache      map[string]string
	mu         sync.RWMutex
}

// NewResolver creates a new SID resolver.
func NewResolver(session *smb.SMBSession) *Resolver {
	return &Resolver{
		smbSession: session,
		cache:      make(map[string]string),
	}
}

// ResolveSIDs resolves a set of SIDs to usernames.
// This requires LSARPC which is not implemented in go-smb2,
// so we fall back to well-known SIDs and caching.
func (r *Resolver) ResolveSIDs(sids []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, sid := range sids {
		if _, ok := r.cache[sid]; ok {
			continue
		}

		// Check for well-known SIDs first
		if name := smb.GetWellKnownName(sid); name != "" {
			r.cache[sid] = name
			continue
		}

		// For unknown SIDs, store the SID itself
		// In a full implementation, we would use LSARPC here
		r.cache[sid] = sid
	}

	return nil
}

// GetSID returns the resolved name for a SID.
func (r *Resolver) GetSID(sid string) string {
	r.mu.RLock()
	if name, ok := r.cache[sid]; ok {
		r.mu.RUnlock()
		return name
	}
	r.mu.RUnlock()

	// Try to resolve
	r.ResolveSIDs([]string{sid})

	r.mu.RLock()
	defer r.mu.RUnlock()
	if name, ok := r.cache[sid]; ok {
		return name
	}
	return sid
}

// CacheSID manually adds a SID to the cache.
func (r *Resolver) CacheSID(sid, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[sid] = name
}

// GetCacheSize returns the number of cached SIDs.
func (r *Resolver) GetCacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}

// Close closes the resolver and releases resources.
func (r *Resolver) Close() {
	// Nothing to close for now
}
