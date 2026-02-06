// Package smb provides SMB session management and security descriptor parsing.
package smb

import (
	"context"
	"fmt"
	"net"
	"path"
	"strings"
	"time"

	"github.com/medianexapp/go-smb2"
	"github.com/specterops/sharehound/internal/config"
	"github.com/specterops/sharehound/internal/credentials"
	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/utils"
)

// ShareInfo holds information about an SMB share.
type ShareInfo struct {
	Name               string
	Type               []string
	RawType            uint32
	Comment            string
	SecurityDescriptor []byte
}

// FileInfo holds information about a file or directory.
type FileInfo struct {
	Name         string
	IsDir        bool
	Size         int64
	CreatedTime  time.Time
	ModifiedTime time.Time
}

// SMBSession represents an SMB session for interacting with an SMB server.
type SMBSession struct {
	config         *config.Config
	log            logger.LoggerInterface
	host           string
	remoteName     string
	port           int
	timeout        time.Duration
	advertisedName string
	credentials    *credentials.Credentials

	conn      net.Conn
	session   *smb2.Session
	share     *smb2.Share
	connected bool

	availableShares map[string]ShareInfo
	currentShare    string
	currentCwd      string

	// SRVSVC client for share-level security descriptors
	srvsvcClient *SRVSVCClient
}

// NewSMBSession creates a new SMBSession.
func NewSMBSession(
	host string,
	port int,
	timeout time.Duration,
	creds *credentials.Credentials,
	remoteName string,
	advertisedName string,
	cfg *config.Config,
	log logger.LoggerInterface,
) *SMBSession {
	if remoteName == "" {
		remoteName = host
	}

	return &SMBSession{
		config:          cfg,
		log:             log,
		host:            host,
		remoteName:      remoteName,
		port:            port,
		timeout:         timeout,
		advertisedName:  advertisedName,
		credentials:     creds,
		availableShares: make(map[string]ShareInfo),
	}
}

// Connect establishes a connection to the SMB server.
func (s *SMBSession) Connect() error {
	s.log.Debug(fmt.Sprintf("[>] Connecting to remote SMB server '%s'...", s.host))

	// Check if port is open first
	ok, err := utils.IsPortOpen(s.host, s.port, s.timeout)
	if !ok {
		s.log.Debug(fmt.Sprintf("Could not connect to '%s:%d', %v", s.host, s.port, err))
		return ErrConnectionFailed
	}

	// Connect to SMB server
	address := fmt.Sprintf("%s:%d", s.host, s.port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		s.log.Debug(fmt.Sprintf("[NETWORK] Could not connect to '%s': %v", address, err))
		return ErrConnectionFailed
	}
	s.conn = conn

	// Create SMB dialer
	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     s.credentials.Username,
			Password: s.credentials.Password,
			Domain:   s.credentials.Domain,
			Hash:     s.credentials.NTRaw,
		},
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// Dial SMB session using DialConn with the existing connection
	session, err := dialer.DialConn(ctx, conn, address)
	if err != nil {
		classification := ClassifyError(err)
		s.log.Debug(fmt.Sprintf("[%s] Authentication failed: %s", classification.Category, classification.Message))
		conn.Close()
		return ErrAuthFailed
	}

	s.session = session
	s.connected = true

	s.log.Debug(fmt.Sprintf("[+] Successfully authenticated to '%s' as '%s\\%s'!",
		s.host, s.credentials.Domain, s.credentials.Username))

	return nil
}

// Close closes the SMB session.
func (s *SMBSession) Close() error {
	if s.srvsvcClient != nil {
		s.srvsvcClient.Close()
		s.srvsvcClient = nil
	}
	if s.share != nil {
		s.share.Umount()
		s.share = nil
	}
	if s.session != nil {
		s.session.Logoff()
		s.session = nil
	}
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.connected = false
	s.log.Debug("[+] SMB connection closed successfully.")
	return nil
}

// IsConnected returns whether the session is connected.
func (s *SMBSession) IsConnected() bool {
	return s.connected && s.session != nil
}

// Ping tests the connection.
func (s *SMBSession) Ping() bool {
	if !s.connected || s.session == nil {
		return false
	}

	// Try to list shares as a ping test
	_, err := s.session.ListSharenames()
	return err == nil
}

// ListShares lists all available shares on the server.
func (s *SMBSession) ListShares() (map[string]ShareInfo, error) {
	if !s.connected {
		return nil, ErrNotConnected
	}

	s.availableShares = make(map[string]ShareInfo)

	names, err := s.session.ListSharenames()
	if err != nil {
		s.log.Debug(fmt.Sprintf("Could not list shares: %v", err))
		return nil, err
	}

	for _, name := range names {
		info := ShareInfo{
			Name: name,
			Type: utils.STYPEMask(0), // go-smb2 doesn't provide share type
		}
		s.availableShares[strings.ToLower(name)] = info
	}

	return s.availableShares, nil
}

// SetShare sets the current share.
func (s *SMBSession) SetShare(shareName string) error {
	if !s.connected {
		return ErrNotConnected
	}

	// Unmount current share if any
	if s.share != nil {
		s.share.Umount()
		s.share = nil
	}

	// Mount the new share
	share, err := s.session.Mount(shareName)
	if err != nil {
		s.log.Debug(fmt.Sprintf("Could not access share '%s': %v", shareName, err))
		return err
	}

	s.share = share
	s.currentShare = shareName
	s.currentCwd = ""

	return nil
}

// GetCurrentShare returns the current share name.
func (s *SMBSession) GetCurrentShare() string {
	return s.currentShare
}

// SetCwd sets the current working directory.
func (s *SMBSession) SetCwd(dir string) {
	s.currentCwd = dir
}

// GetCwd returns the current working directory.
func (s *SMBSession) GetCwd() string {
	return s.currentCwd
}

// ListContents lists the contents of a directory.
func (s *SMBSession) ListContents(dirPath string) (map[string]FileInfo, error) {
	if s.share == nil {
		return nil, ErrShareNotSet
	}

	// Build full path
	fullPath := dirPath
	if s.currentCwd != "" && !strings.HasPrefix(dirPath, "\\") && !strings.HasPrefix(dirPath, "/") {
		fullPath = path.Join(s.currentCwd, dirPath)
	}

	// Normalize path separators
	fullPath = strings.ReplaceAll(fullPath, "/", "\\")
	if fullPath == "" {
		fullPath = "."
	}

	contents := make(map[string]FileInfo)

	entries, err := s.share.ReadDir(fullPath)
	if err != nil {
		s.log.Debug(fmt.Sprintf("Error listing contents of '%s': %v", fullPath, err))
		return nil, err
	}

	for _, info := range entries {
		fi := FileInfo{
			Name:         info.Name(),
			IsDir:        info.IsDir(),
			Size:         info.Size(),
			ModifiedTime: info.ModTime(),
		}
		// Try to get creation time from underlying FileStat
		if fileStat, ok := info.(*smb2.FileStat); ok {
			fi.CreatedTime = fileStat.CreationTime
		}
		contents[info.Name()] = fi
	}

	return contents, nil
}

// GetFileSecurityDescriptor gets the NTFS security descriptor for a file or directory.
// This uses the medianexapp/go-smb2 fork which has native SecurityInfoRaw() support.
func (s *SMBSession) GetFileSecurityDescriptor(filePath string) (*SecurityDescriptor, error) {
	if s.share == nil {
		return nil, ErrShareNotSet
	}

	// Normalize path
	fullPath := strings.ReplaceAll(filePath, "/", "\\")
	if fullPath == "" {
		fullPath = "."
	}

	// Try to get security descriptor using go:linkname approach
	sdBytes, err := QuerySecurityDescriptorLinked(s.share, fullPath)
	if err != nil {
		// Log debug but don't fail - this is expected in some cases
		s.log.Debug(fmt.Sprintf("Could not get security descriptor for '%s': %v", fullPath, err))
		return nil, nil
	}

	if len(sdBytes) == 0 {
		return nil, nil
	}

	// Parse the security descriptor
	return ParseSecurityDescriptor(sdBytes)
}

// GetShareSecurityDescriptor gets the share-level security descriptor via SRVSVC RPC.
func (s *SMBSession) GetShareSecurityDescriptor(shareName string) ([]byte, error) {
	if !s.connected {
		return nil, ErrNotConnected
	}

	// Try to initialize SRVSVC client if not already done
	if s.srvsvcClient == nil {
		client, err := NewSRVSVCClient(s.session)
		if err != nil {
			s.log.Debug(fmt.Sprintf("Failed to create SRVSVC client: %v", err))
			return nil, fmt.Errorf("SRVSVC not available: %w", err)
		}
		s.srvsvcClient = client
	}

	// Query share security descriptor via SRVSVC
	sd, err := s.srvsvcClient.GetShareSecurityDescriptor(s.remoteName, shareName)
	if err != nil {
		s.log.Debug(fmt.Sprintf("Failed to get share security descriptor via SRVSVC: %v", err))
		return nil, err
	}

	return sd, nil
}

// GetShareRootSecurityDescriptor gets the NTFS security descriptor of the share root.
// This is used as a fallback when SRVSVC is not available.
func (s *SMBSession) GetShareRootSecurityDescriptor(shareName string) ([]byte, error) {
	// Save current share
	originalShare := s.currentShare

	// Connect to target share
	if err := s.SetShare(shareName); err != nil {
		return nil, err
	}

	defer func() {
		// Restore original share if any
		if originalShare != "" {
			s.SetShare(originalShare)
		}
	}()

	// Try to open root and verify access
	f, err := s.share.Open(".")
	if err != nil {
		return nil, fmt.Errorf("failed to open share root: %w", err)
	}
	defer f.Close()

	// Get file stat to verify we have access
	_, err = f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat share root: %w", err)
	}

	// go-smb2 doesn't expose security descriptor queries
	// Log that we have access but can't get SD
	s.log.Debug(fmt.Sprintf("Share root '%s' accessible but SD query not supported", shareName))
	return nil, ErrSecurityDescriptorNotSupported
}

// GetSession returns the underlying SMB2 session.
func (s *SMBSession) GetSession() *smb2.Session {
	return s.session
}

// GetRemoteName returns the remote server name.
func (s *SMBSession) GetRemoteName() string {
	return s.remoteName
}

// GetRemoteHost returns the remote host IP/hostname.
func (s *SMBSession) GetRemoteHost() string {
	return s.host
}
