// Package smb provides SMB session management and security descriptor parsing.
//
// Integration tests for SMB functionality.
// Run with: go test -v -tags=integration ./internal/smb -run TestIntegration
//
// Required environment variables:
//   SMB_TEST_HOST     - SMB server hostname or IP
//   SMB_TEST_USER     - Username for authentication
//   SMB_TEST_PASSWORD - Password for authentication
//   SMB_TEST_DOMAIN   - Domain (optional, defaults to "")
//   SMB_TEST_SHARE    - Share name to test (optional, defaults to first available)
package smb

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/specterops/sharehound/internal/config"
	"github.com/specterops/sharehound/internal/credentials"
)

// testLogger implements logger.LoggerInterface for testing
type testLogger struct {
	t      *testing.T
	indent int
	cfg    *config.Config
}

func newTestLogger(t *testing.T) *testLogger {
	return &testLogger{t: t, cfg: &config.Config{}}
}

func (l *testLogger) Print(msg string) {
	if l.t != nil {
		l.t.Logf("%s", msg)
	}
}
func (l *testLogger) PrintWithEnd(msg string, _ string) {
	if l.t != nil {
		l.t.Logf("%s", msg)
	}
}
func (l *testLogger) Debug(msg string) {
	if l.t != nil {
		l.t.Logf("[DEBUG] %s", msg)
	}
}
func (l *testLogger) Info(msg string) {
	if l.t != nil {
		l.t.Logf("[INFO] %s", msg)
	}
}
func (l *testLogger) Warning(msg string) {
	if l.t != nil {
		l.t.Logf("[WARN] %s", msg)
	}
}
func (l *testLogger) Error(msg string) {
	if l.t != nil {
		l.t.Logf("[ERROR] %s", msg)
	}
}
func (l *testLogger) Critical(msg string) {
	if l.t != nil {
		l.t.Logf("[CRITICAL] %s", msg)
	}
}
func (l *testLogger) IncrementIndent()       { l.indent++ }
func (l *testLogger) DecrementIndent()       { l.indent-- }
func (l *testLogger) Config() *config.Config { return l.cfg }

func getTestConfig() (host, user, password, domain, share string, skip bool) {
	host = os.Getenv("SMB_TEST_HOST")
	user = os.Getenv("SMB_TEST_USER")
	password = os.Getenv("SMB_TEST_PASSWORD")
	domain = os.Getenv("SMB_TEST_DOMAIN")
	share = os.Getenv("SMB_TEST_SHARE")

	if host == "" || user == "" || password == "" {
		return "", "", "", "", "", true
	}
	return host, user, password, domain, share, false
}

// TestIntegrationConnect tests basic SMB connection
func TestIntegrationConnect(t *testing.T) {
	host, user, password, domain, _, skip := getTestConfig()
	if skip {
		t.Skip("SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASSWORD not set")
	}

	log := newTestLogger(t)
	creds := &credentials.Credentials{
		Username: user,
		Password: password,
		Domain:   domain,
	}

	cfg := &config.Config{}
	session := NewSMBSession(host, 445, 30*time.Second, creds, "", "", cfg, log)

	err := session.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer session.Close()

	t.Log("Successfully connected to SMB server")
}

// TestIntegrationListShares tests listing available shares
func TestIntegrationListShares(t *testing.T) {
	host, user, password, domain, _, skip := getTestConfig()
	if skip {
		t.Skip("SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASSWORD not set")
	}

	log := newTestLogger(t)
	creds := &credentials.Credentials{
		Username: user,
		Password: password,
		Domain:   domain,
	}

	cfg := &config.Config{}
	session := NewSMBSession(host, 445, 30*time.Second, creds, "", "", cfg, log)

	err := session.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer session.Close()

	shares, err := session.ListShares()
	if err != nil {
		t.Fatalf("Failed to list shares: %v", err)
	}

	t.Logf("Found %d shares:", len(shares))
	for name, info := range shares {
		t.Logf("  - %s (type: %v, comment: %s)", name, info.Type, info.Comment)
	}

	if len(shares) == 0 {
		t.Error("Expected at least one share")
	}
}

// TestIntegrationListContents tests listing directory contents
func TestIntegrationListContents(t *testing.T) {
	host, user, password, domain, share, skip := getTestConfig()
	if skip {
		t.Skip("SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASSWORD not set")
	}

	log := newTestLogger(t)
	creds := &credentials.Credentials{
		Username: user,
		Password: password,
		Domain:   domain,
	}

	cfg := &config.Config{}
	session := NewSMBSession(host, 445, 30*time.Second, creds, "", "", cfg, log)

	err := session.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer session.Close()

	// Get first available share if not specified
	if share == "" {
		shares, err := session.ListShares()
		if err != nil {
			t.Fatalf("Failed to list shares: %v", err)
		}
		for name, info := range shares {
			// Skip admin shares
			if name != "IPC$" && name != "ADMIN$" && name != "C$" && name != "PRINT$" {
				// Check if it's a disk share
				for _, stype := range info.Type {
					if stype == "DISK" {
						share = name
						break
					}
				}
			}
			if share != "" {
				break
			}
		}
	}

	if share == "" {
		t.Skip("No suitable share found for testing")
	}

	t.Logf("Testing with share: %s", share)

	err = session.SetShare(share)
	if err != nil {
		t.Fatalf("Failed to set share: %v", err)
	}

	contents, err := session.ListContents("")
	if err != nil {
		t.Fatalf("Failed to list contents: %v", err)
	}

	t.Logf("Found %d items in share root:", len(contents))
	count := 0
	for name, info := range contents {
		typeStr := "FILE"
		if info.IsDir {
			typeStr = "DIR"
		}
		t.Logf("  [%s] %s (size: %d, modified: %v, created: %v)",
			typeStr, name, info.Size, info.ModifiedTime, info.CreatedTime)
		count++
		if count >= 10 {
			t.Logf("  ... and %d more items", len(contents)-10)
			break
		}
	}
}

// TestIntegrationSecurityDescriptor tests retrieving NTFS security descriptors
func TestIntegrationSecurityDescriptor(t *testing.T) {
	host, user, password, domain, share, skip := getTestConfig()
	if skip {
		t.Skip("SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASSWORD not set")
	}

	log := newTestLogger(t)
	creds := &credentials.Credentials{
		Username: user,
		Password: password,
		Domain:   domain,
	}

	cfg := &config.Config{}
	session := NewSMBSession(host, 445, 30*time.Second, creds, "", "", cfg, log)

	err := session.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer session.Close()

	// Get first available share if not specified
	if share == "" {
		shares, err := session.ListShares()
		if err != nil {
			t.Fatalf("Failed to list shares: %v", err)
		}
		for name, info := range shares {
			if name != "IPC$" && name != "ADMIN$" && name != "C$" && name != "PRINT$" {
				for _, stype := range info.Type {
					if stype == "DISK" {
						share = name
						break
					}
				}
			}
			if share != "" {
				break
			}
		}
	}

	if share == "" {
		t.Skip("No suitable share found for testing")
	}

	t.Logf("Testing security descriptors on share: %s", share)

	err = session.SetShare(share)
	if err != nil {
		t.Fatalf("Failed to set share: %v", err)
	}

	// Test on root directory
	sd, err := session.GetFileSecurityDescriptor(".")
	if err != nil {
		t.Logf("Could not get security descriptor for root: %v", err)
	} else if sd == nil {
		t.Log("Security descriptor for root is nil (access denied or not supported)")
	} else {
		t.Logf("Got security descriptor for root:")
		t.Logf("  Revision: %d", sd.Revision)
		if sd.OwnerSID != nil {
			t.Logf("  Owner SID: %s", sd.OwnerSID.String())
		}
		if sd.GroupSID != nil {
			t.Logf("  Group SID: %s", sd.GroupSID.String())
		}
		if sd.Dacl != nil {
			t.Logf("  DACL has %d ACEs:", len(sd.Dacl.Aces))
			for i, ace := range sd.Dacl.Aces {
				if ace.SID != nil {
					rights := GetNTFSRightsForMask(ace.Mask)
					t.Logf("    ACE %d: Type=%d, SID=%s, Mask=0x%08x, Rights=%v",
						i, ace.AceType, ace.SID.String(), ace.Mask, rights)
				}
				if i >= 5 {
					t.Logf("    ... and %d more ACEs", len(sd.Dacl.Aces)-6)
					break
				}
			}
		}
	}

	// Also test on first file/directory found
	contents, err := session.ListContents("")
	if err == nil && len(contents) > 0 {
		for name, info := range contents {
			if name == "." || name == ".." {
				continue
			}
			t.Logf("\nTesting security descriptor for: %s", name)
			sd, err := session.GetFileSecurityDescriptor(name)
			if err != nil {
				t.Logf("  Could not get security descriptor: %v", err)
			} else if sd == nil {
				t.Log("  Security descriptor is nil")
			} else {
				t.Logf("  Got security descriptor (DACL has %d ACEs)", len(sd.Dacl.Aces))
				if sd.OwnerSID != nil {
					t.Logf("  Owner: %s", sd.OwnerSID.String())
				}
			}

			// Test just the first item
			_ = info
			break
		}
	}
}

// TestIntegrationDirectoryTraversal tests recursive directory traversal
func TestIntegrationDirectoryTraversal(t *testing.T) {
	host, user, password, domain, share, skip := getTestConfig()
	if skip {
		t.Skip("SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASSWORD not set")
	}

	log := newTestLogger(t)
	creds := &credentials.Credentials{
		Username: user,
		Password: password,
		Domain:   domain,
	}

	cfg := &config.Config{}
	session := NewSMBSession(host, 445, 30*time.Second, creds, "", "", cfg, log)

	err := session.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer session.Close()

	// Get first available share if not specified
	if share == "" {
		shares, err := session.ListShares()
		if err != nil {
			t.Fatalf("Failed to list shares: %v", err)
		}
		for name, info := range shares {
			if name != "IPC$" && name != "ADMIN$" && name != "C$" && name != "PRINT$" {
				for _, stype := range info.Type {
					if stype == "DISK" {
						share = name
						break
					}
				}
			}
			if share != "" {
				break
			}
		}
	}

	if share == "" {
		t.Skip("No suitable share found for testing")
	}

	t.Logf("Testing directory traversal on share: %s", share)

	err = session.SetShare(share)
	if err != nil {
		t.Fatalf("Failed to set share: %v", err)
	}

	// Traverse up to 3 levels deep
	totalFiles := 0
	totalDirs := 0
	totalWithSD := 0

	var traverse func(path string, depth int)
	traverse = func(path string, depth int) {
		if depth > 3 {
			return
		}

		contents, err := session.ListContents(path)
		if err != nil {
			t.Logf("Error listing %s: %v", path, err)
			return
		}

		for name, info := range contents {
			if name == "." || name == ".." {
				continue
			}

			fullPath := name
			if path != "" {
				fullPath = path + "\\" + name
			}

			if info.IsDir {
				totalDirs++
				traverse(fullPath, depth+1)
			} else {
				totalFiles++
			}

			// Check if we can get security descriptor
			sd, _ := session.GetFileSecurityDescriptor(fullPath)
			if sd != nil {
				totalWithSD++
			}

			// Limit to prevent long-running tests
			if totalFiles+totalDirs > 100 {
				return
			}
		}
	}

	traverse("", 0)

	t.Logf("Traversal results:")
	t.Logf("  Total directories: %d", totalDirs)
	t.Logf("  Total files: %d", totalFiles)
	t.Logf("  Items with security descriptors: %d", totalWithSD)

	if totalFiles == 0 && totalDirs == 0 {
		t.Log("Warning: No files or directories found")
	}
}

// TestIntegrationShareSecurityDescriptor tests getting share-level security descriptors via SRVSVC
func TestIntegrationShareSecurityDescriptor(t *testing.T) {
	host, user, password, domain, share, skip := getTestConfig()
	if skip {
		t.Skip("SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASSWORD not set")
	}

	log := newTestLogger(t)
	creds := &credentials.Credentials{
		Username: user,
		Password: password,
		Domain:   domain,
	}

	cfg := &config.Config{}
	session := NewSMBSession(host, 445, 30*time.Second, creds, "", "", cfg, log)

	err := session.Connect()
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer session.Close()

	// Get first available share if not specified
	if share == "" {
		shares, err := session.ListShares()
		if err != nil {
			t.Fatalf("Failed to list shares: %v", err)
		}
		for name, info := range shares {
			if name != "IPC$" && name != "ADMIN$" && name != "C$" && name != "PRINT$" {
				for _, stype := range info.Type {
					if stype == "DISK" {
						share = name
						break
					}
				}
			}
			if share != "" {
				break
			}
		}
	}

	if share == "" {
		t.Skip("No suitable share found for testing")
	}

	t.Logf("Testing share-level security descriptor for: %s", share)

	sdBytes, err := session.GetShareSecurityDescriptor(share)
	if err != nil {
		t.Logf("Could not get share security descriptor: %v", err)
		t.Log("This may be expected if SRVSVC RPC is not available or user lacks permissions")
		return
	}

	if sdBytes == nil {
		t.Log("Share security descriptor is nil")
		return
	}

	t.Logf("Got share security descriptor (%d bytes)", len(sdBytes))

	// Try to parse it
	sd, err := ParseSecurityDescriptor(sdBytes)
	if err != nil {
		t.Logf("Could not parse security descriptor: %v", err)
		return
	}

	t.Logf("Parsed share security descriptor:")
	if sd.OwnerSID != nil {
		t.Logf("  Owner: %s", sd.OwnerSID.String())
	}
	if sd.Dacl != nil {
		t.Logf("  DACL has %d ACEs", len(sd.Dacl.Aces))
		for i, ace := range sd.Dacl.Aces {
			if ace.SID != nil {
				t.Logf("    ACE %d: SID=%s, Mask=0x%08x", i, ace.SID.String(), ace.Mask)
			}
		}
	}
}

// BenchmarkListContents benchmarks directory listing performance
func BenchmarkListContents(b *testing.B) {
	host, user, password, domain, share, skip := getTestConfig()
	if skip {
		b.Skip("SMB_TEST_HOST, SMB_TEST_USER, SMB_TEST_PASSWORD not set")
	}

	log := &testLogger{t: nil, cfg: &config.Config{}} // Suppress output
	creds := &credentials.Credentials{
		Username: user,
		Password: password,
		Domain:   domain,
	}

	cfg := &config.Config{}
	session := NewSMBSession(host, 445, 30*time.Second, creds, "", "", cfg, log)

	err := session.Connect()
	if err != nil {
		b.Fatalf("Failed to connect: %v", err)
	}
	defer session.Close()

	if share == "" {
		shares, _ := session.ListShares()
		for name, info := range shares {
			if name != "IPC$" && name != "ADMIN$" && name != "C$" && name != "PRINT$" {
				for _, stype := range info.Type {
					if stype == "DISK" {
						share = name
						break
					}
				}
			}
			if share != "" {
				break
			}
		}
	}

	if share == "" {
		b.Skip("No suitable share found")
	}

	session.SetShare(share)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := session.ListContents("")
		if err != nil {
			b.Fatalf("ListContents failed: %v", err)
		}
	}
}

// Example usage for documentation
func Example_connectAndListShares() {
	// Create credentials
	creds := &credentials.Credentials{
		Username: "testuser",
		Password: "testpassword",
		Domain:   "TESTDOMAIN",
	}

	// Create a simple logger that prints to stdout
	log := &testLogger{cfg: &config.Config{}}

	// Create session
	cfg := &config.Config{}
	session := NewSMBSession("192.168.1.100", 445, 30*time.Second, creds, "", "", cfg, log)

	// Connect
	err := session.Connect()
	if err != nil {
		fmt.Printf("Connection failed: %v\n", err)
		return
	}
	defer session.Close()

	// List shares
	shares, err := session.ListShares()
	if err != nil {
		fmt.Printf("Failed to list shares: %v\n", err)
		return
	}

	for name := range shares {
		fmt.Printf("Share: %s\n", name)
	}
}
