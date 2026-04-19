// Package worker provides worker pool and task management.
package worker

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/specterops/sharehound/internal/config"
	"github.com/specterops/sharehound/internal/credentials"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/smb"
)

// ConnectionPool manages SMB session connections per host with connection reuse.
type ConnectionPool struct {
	maxConnectionsPerHost int
	connections           map[string][]*smb.SMBSession
	activeConnections     map[*smb.SMBSession]bool // Track connections currently in use
	mu                    sync.Mutex
}

// NewConnectionPool creates a new ConnectionPool.
func NewConnectionPool(maxConnectionsPerHost int) *ConnectionPool {
	return &ConnectionPool{
		maxConnectionsPerHost: maxConnectionsPerHost,
		connections:           make(map[string][]*smb.SMBSession),
		activeConnections:     make(map[*smb.SMBSession]bool),
	}
}

// GetConnection gets an available connection for the host, creating one if needed.
func (p *ConnectionPool) GetConnection(
	host, remoteName string,
	creds *credentials.Credentials,
	timeout time.Duration,
	advertisedName string,
	cfg *config.Config,
	log logger.LoggerInterface,
) (*smb.SMBSession, error) {
	p.mu.Lock()

	// Try to reuse an existing connection
	if conns, ok := p.connections[host]; ok && len(conns) > 0 {
		conn := conns[len(conns)-1]
		p.connections[host] = conns[:len(conns)-1]
		p.activeConnections[conn] = true
		p.mu.Unlock()

		if conn.Ping() {
			return conn, nil
		}
		// Connection is dead, close it and remove from active
		p.mu.Lock()
		delete(p.activeConnections, conn)
		p.mu.Unlock()
		conn.Close()
	} else {
		p.mu.Unlock()
	}

	// Create new connection
	session := smb.NewSMBSession(
		host,
		445,
		timeout,
		creds,
		remoteName,
		advertisedName,
		cfg,
		log,
	)

	// Track as active BEFORE Connect() so timeout can close it if stuck
	p.mu.Lock()
	p.activeConnections[session] = true
	p.mu.Unlock()

	if err := session.Connect(); err != nil {
		// Remove from active on failure
		p.mu.Lock()
		delete(p.activeConnections, session)
		p.mu.Unlock()
		return nil, err
	}

	return session, nil
}

// ReturnConnection returns a connection to the pool for reuse.
func (p *ConnectionPool) ReturnConnection(host string, conn *smb.SMBSession) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Remove from active connections
	delete(p.activeConnections, conn)

	if len(p.connections[host]) < p.maxConnectionsPerHost {
		p.connections[host] = append(p.connections[host], conn)
	} else {
		// Pool is full, close the connection
		conn.Close()
	}
}

// CloseAll closes all connections in the pool.
func (p *ConnectionPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conns := range p.connections {
		for _, conn := range conns {
			conn.Close()
		}
	}
	p.connections = make(map[string][]*smb.SMBSession)
}

// ForceCloseAll forcefully closes all connections, interrupting any blocking operations.
// This includes both pooled connections and connections currently in use.
func (p *ConnectionPool) ForceCloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	activeCount := len(p.activeConnections)
	pooledCount := 0
	for _, conns := range p.connections {
		pooledCount += len(conns)
	}

	if activeCount > 0 || pooledCount > 0 {
		fmt.Fprintf(os.Stderr, "[FORCECLOSE] Closing %d active + %d pooled connections\n", activeCount, pooledCount)
	}

	// Force close all active (in-use) connections first
	for conn := range p.activeConnections {
		conn.ForceClose()
	}
	p.activeConnections = make(map[*smb.SMBSession]bool)

	// Then close pooled connections
	for _, conns := range p.connections {
		for _, conn := range conns {
			conn.ForceClose()
		}
	}
	p.connections = make(map[string][]*smb.SMBSession)
}
