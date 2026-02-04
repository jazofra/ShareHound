# ShareHound Go Port Plan

A comprehensive plan to port ShareHound from Python to Go with complete feature parity.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Structure](#2-project-structure)
3. [Dependencies and Libraries](#3-dependencies-and-libraries)
4. [Module-by-Module Porting Guide](#4-module-by-module-porting-guide)
5. [Node Types (Feature Parity)](#5-node-types-feature-parity)
6. [Edge Types (Feature Parity)](#6-edge-types-feature-parity)
7. [Output Format](#7-output-format)
8. [Implementation Phases](#8-implementation-phases)
9. [Testing Strategy](#9-testing-strategy)
10. [Risk Assessment](#10-risk-assessment)

---

## 1. Executive Summary

### Current Python Implementation

- **Language**: Python 3.11+
- **Lines of Code**: ~5,200 lines across 27 files
- **Core Dependencies**: impacket, bhopengraph, sectools, shareql, pycryptodome, lark, rich

### Go Port Estimates

- **Estimated Lines**: 8,000-12,000 lines (Go is more verbose for system-level code)
- **Estimated Files**: 30-40 Go files
- **Complexity**: Medium-High

### Key Challenges

1. **SMB Protocol Implementation**: Need Go SMB library with equivalent capabilities to impacket
2. **DCERPC Support**: SID resolution via LSARPC, SRVSVC for share enumeration
3. **Security Descriptor Parsing**: Binary parsing of Windows security descriptors
4. **ShareQL Rule Engine**: Parser and evaluator for the ShareQL DSL
5. **BloodHound OpenGraph**: JSON output format compatibility

---

## 2. Project Structure

```
sharehound-go/
├── cmd/
│   └── sharehound/
│       └── main.go                 # Entry point, CLI argument parsing
├── internal/
│   ├── config/
│   │   └── config.go               # Configuration management
│   ├── credentials/
│   │   └── credentials.go          # Authentication credentials handling
│   ├── logger/
│   │   ├── logger.go               # Main logger
│   │   └── tasklogger.go           # Task-specific logger
│   ├── smb/
│   │   ├── session.go              # SMBSession equivalent
│   │   ├── error_classifier.go     # SMBErrorClassifier
│   │   ├── dialects.go             # SMB dialect fallback logic
│   │   └── security_descriptor.go  # Security descriptor parsing
│   ├── dcerpc/
│   │   ├── lsarpc.go               # LSARPC for SID resolution
│   │   ├── srvsvc.go               # SRVSVC for share enumeration
│   │   └── winreg.go               # Remote registry access
│   ├── sid/
│   │   └── resolver.go             # SIDResolver
│   ├── collector/
│   │   ├── share_rights.go         # collect_share_rights
│   │   ├── ntfs_rights.go          # collect_ntfs_rights
│   │   ├── contents.go             # collect_contents_in_share
│   │   └── depth_traversal.go      # collect_contents_at_depth (BFS)
│   ├── graph/
│   │   ├── context.go              # OpenGraphContext
│   │   ├── node.go                 # Node types
│   │   ├── edge.go                 # Edge types
│   │   └── opengraph.go            # OpenGraph builder
│   ├── rules/
│   │   ├── parser.go               # ShareQL parser
│   │   ├── evaluator.go            # Rules evaluator
│   │   └── objects.go              # RuleObjectShare, RuleObjectFile, RuleObjectDirectory
│   ├── targets/
│   │   └── loader.go               # Target enumeration (AD, file, CLI)
│   ├── worker/
│   │   ├── worker.go               # Main worker logic
│   │   ├── pool.go                 # ConnectionPool
│   │   └── share_task.go           # process_share_task
│   └── utils/
│       ├── dns.go                  # DNS resolution
│       ├── network.go              # Port checking
│       ├── filesize.go             # Human-readable file sizes
│       ├── stype.go                # STYPE_MASK share type flags
│       └── hash.go                 # LM/NT hash parsing
├── pkg/
│   └── kinds/
│       └── kinds.go                # Node and edge kind constants
├── go.mod
├── go.sum
└── Makefile
```

---

## 3. Dependencies and Libraries

### Critical Go Libraries Required

| Component | Python Library | Recommended Go Library | Notes |
|-----------|---------------|------------------------|-------|
| SMB Client | impacket | `github.com/hirochachacha/go-smb2` | Most mature Go SMB2/3 library |
| DCERPC | impacket.dcerpc.v5 | Custom implementation or `github.com/oiweiwei/go-msrpc` | May need custom LSARPC/SRVSVC |
| LDAP | ldap3 (via sectools) | `github.com/go-ldap/ldap/v3` | AD queries |
| DNS | dnspython | `github.com/miekg/dns` or stdlib | DNS resolution |
| CLI | argparse | `github.com/spf13/cobra` or stdlib `flag` | Argument parsing |
| Progress UI | rich | `github.com/schollz/progressbar/v3` or `github.com/charmbracelet/bubbletea` | Terminal UI |
| JSON | stdlib | stdlib `encoding/json` | Output format |
| Parser (ShareQL) | lark | `github.com/alecthomas/participle/v2` | Grammar parsing |
| Kerberos | impacket | `github.com/jcmturner/gokrb5/v8` | Kerberos auth |
| Crypto | pycryptodome | stdlib `crypto/*` | NT hash, AES |

### Go Module Dependencies

```go
// go.mod
module github.com/specterops/sharehound

go 1.21

require (
    github.com/hirochachacha/go-smb2 v1.1.0
    github.com/go-ldap/ldap/v3 v3.4.6
    github.com/miekg/dns v1.1.57
    github.com/spf13/cobra v1.8.0
    github.com/jcmturner/gokrb5/v8 v8.4.4
    github.com/alecthomas/participle/v2 v2.1.1
    github.com/schollz/progressbar/v3 v3.14.1
    github.com/fatih/color v1.16.0
)
```

---

## 4. Module-by-Module Porting Guide

### 4.1 CLI and Entry Point (`cmd/sharehound/main.go`)

**Python Source**: `sharehound/__main__.py` (456 lines)

**Key Functions to Port**:
- `parseArgs()` → Use `cobra` or stdlib `flag`
- `parse_rules()` → Rule parsing
- `main()` → Orchestration

**CLI Arguments** (must maintain exact same flags):

```go
type Options struct {
    // Output options
    Verbose     bool
    Debug       bool
    NoColors    bool
    Logfile     string
    Output      string

    // Advanced configuration
    AdvertisedName   string
    Threads          int
    MaxWorkersPerHost int
    GlobalMaxWorkers int
    Nameserver       string
    Timeout          float64
    HostTimeout      float64

    // Rules
    RulesFiles  []string
    RuleStrings []string

    // Share exploration
    Share              string
    Depth              int
    IncludeCommonShares bool

    // Targets and authentication
    TargetsFile  string
    Targets      []string
    AuthDomain   string
    AuthDCIP     string
    AuthUser     string
    AuthPassword string
    AuthHashes   string
    AuthKey      string
    UseKerberos  bool
    KDCHost      string
    UseLDAPS     bool
    Subnets      bool
}
```

**Default Rules** (must be identical):
```go
var DefaultRules = []string{
    "DEFAULT: ALLOW",
    "DENY EXPLORATION IF SHARE.NAME IN ['c$','print$','admin$','ipc$']",
    "ALLOW EXPLORATION",
}
```

---

### 4.2 Configuration (`internal/config/config.go`)

**Python Source**: `sharehound/core/Config.py` (91 lines)

```go
package config

type Config struct {
    Debug    bool
    NoColors bool
}

func NewConfig(debug bool, noColors *bool) *Config {
    cfg := &Config{Debug: debug}
    if noColors != nil {
        cfg.NoColors = *noColors
    } else {
        // Platform-specific default
        if runtime.GOOS == "windows" {
            cfg.NoColors = false
        } else {
            cfg.NoColors = true
        }
    }
    return cfg
}
```

---

### 4.3 Credentials (`internal/credentials/credentials.go`)

**Python Source**: `sharehound/core/Credentials.py` (147 lines)

```go
package credentials

type Credentials struct {
    Domain      string
    Username    string
    Password    string
    NTHex       string
    NTRaw       []byte
    LMHex       string
    LMRaw       []byte
    UseKerberos bool
    AESKey      string
    KDCHost     string
}

func NewCredentials(domain, username, password string, hashes *string,
    useKerberos bool, aesKey, kdcHost *string) *Credentials {
    c := &Credentials{
        Domain:      domain,
        Username:    username,
        Password:    password,
        UseKerberos: useKerberos,
    }
    if aesKey != nil {
        c.AESKey = *aesKey
    }
    if kdcHost != nil {
        c.KDCHost = *kdcHost
    }
    if hashes != nil {
        c.SetHashes(*hashes)
    }
    return c
}

func (c *Credentials) SetHashes(hashes string) {
    // Parse LM:NT format
    c.LMHex, c.NTHex = parseLMNTHashes(hashes)
    if c.LMHex != "" {
        c.LMRaw, _ = hex.DecodeString(c.LMHex)
    }
    if c.NTHex != "" {
        c.NTRaw, _ = hex.DecodeString(c.NTHex)
    }
}

func (c *Credentials) IsAnonymous() bool {
    return c.Username == ""
}

func (c *Credentials) CanPassTheHash() bool {
    return c.NTHex != "" && c.LMHex != ""
}
```

---

### 4.4 Logger (`internal/logger/logger.go`)

**Python Source**: `sharehound/core/Logger.py` (297 lines)

```go
package logger

type LogLevel int

const (
    INFO LogLevel = iota
    DEBUG
    WARNING
    ERROR
    CRITICAL
)

type Logger struct {
    config      *config.Config
    logfile     *os.File
    indentLevel int
    mu          sync.Mutex
}

func NewLogger(cfg *config.Config, logfilePath string) *Logger {
    l := &Logger{config: cfg}
    if logfilePath != "" {
        // Handle file rotation like Python version
        l.logfile = openLogFile(logfilePath)
    }
    return l
}

func (l *Logger) getTimestampAndIndent() (string, string) {
    now := time.Now()
    timestamp := now.Format("2006-01-02 15:04:05") +
                 fmt.Sprintf(".%03d", now.Nanosecond()/1e6)
    indent := strings.Repeat("  │ ", l.indentLevel)
    return timestamp, indent
}

func (l *Logger) Info(message string)     { /* ... */ }
func (l *Logger) Debug(message string)    { /* ... */ }
func (l *Logger) Error(message string)    { /* ... */ }
func (l *Logger) Warning(message string)  { /* ... */ }
func (l *Logger) IncrementIndent()        { l.indentLevel++ }
func (l *Logger) DecrementIndent()        { if l.indentLevel > 0 { l.indentLevel-- } }

// TaskLogger for concurrent task isolation
type TaskLogger struct {
    baseLogger  *Logger
    taskID      string
    indentLevel int
}
```

---

### 4.5 SMB Session (`internal/smb/session.go`)

**Python Source**: `sharehound/core/SMBSession.py` (1,098 lines)

This is the most complex module. Key components:

```go
package smb

import (
    "github.com/hirochachacha/go-smb2"
)

type SMBSession struct {
    config         *config.Config
    logger         *logger.Logger
    host           string
    remoteName     string
    port           int
    timeout        time.Duration
    advertisedName string
    credentials    *credentials.Credentials

    conn           net.Conn
    session        *smb2.Session
    share          *smb2.Share
    connected      bool

    availableShares map[string]ShareInfo
    currentShare    string
    currentCwd      string
    treeID          uint32

    sidResolver *SIDResolver
}

// ShareInfo holds share metadata
type ShareInfo struct {
    Name               string
    Type               []string
    RawType            uint32
    Comment            string
    SecurityDescriptor []byte
}

// SMBErrorClassifier - port exactly as in Python
type SMBErrorClassifier struct{}

const (
    STATUS_NOT_SUPPORTED     = 0xc00000bb
    STATUS_ACCESS_DENIED     = 0xc0000022
    STATUS_LOGON_FAILURE     = 0xc000006d
    // ... all other status codes
)

func (c *SMBErrorClassifier) Classify(err error) (category, message string, shouldRetry bool) {
    // Exact same logic as Python
}

// Key methods to implement:
func (s *SMBSession) InitSMBSession() bool {
    // Implement dialect fallback: auto-negotiate -> SMB3 -> SMB2.1 -> SMB2 -> SMB1
}

func (s *SMBSession) ListShares() map[string]ShareInfo {
    // Use SRVSVC RPC to get detailed share info (level 502)
    // Fall back to basic share list if detailed fails
}

func (s *SMBSession) GetShareSecurityDescriptor(shareName string) ([]byte, error) {
    // 1. Try NetrShareGetInfo level 502
    // 2. Fall back to remote registry queries
}

func (s *SMBSession) GetShareRootSecurityDescriptor(shareName string) ([]byte, error) {
    // Fall back: get NTFS security descriptor of share root folder
}

func (s *SMBSession) GetEntrySecurityDescriptor(path string, entry os.FileInfo) (*SecurityDescriptor, error) {
    // Get NTFS security descriptor for file/directory
}

func (s *SMBSession) ListContents(path string) (map[string]os.FileInfo, error) {
    // List directory contents
}

func (s *SMBSession) SetShare(shareName string) error { /* ... */ }
func (s *SMBSession) SetCwd(path string) error { /* ... */ }
func (s *SMBSession) Close() error { /* ... */ }
```

---

### 4.6 Security Descriptor Parsing (`internal/smb/security_descriptor.go`)

**Critical**: Must parse Windows security descriptors exactly like impacket's `ldaptypes.SR_SECURITY_DESCRIPTOR`

```go
package smb

// SecurityDescriptor represents a Windows security descriptor
type SecurityDescriptor struct {
    Revision    byte
    Sbz1        byte
    Control     uint16
    OwnerSID    *SID
    GroupSID    *SID
    Sacl        *ACL  // System ACL (usually ignored)
    Dacl        *ACL  // Discretionary ACL (this is what we process)
}

// ACL represents an Access Control List
type ACL struct {
    AclRevision byte
    Sbz1        byte
    AclSize     uint16
    AceCount    uint16
    Sbz2        uint16
    Aces        []ACE
}

// ACE represents an Access Control Entry
type ACE struct {
    AceType  byte
    AceFlags byte
    AceSize  uint16
    Mask     uint32
    SID      *SID
}

// ACE Types
const (
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE  = 0x01
    // ... other types
)

// SID represents a Security Identifier
type SID struct {
    Revision            byte
    SubAuthorityCount   byte
    IdentifierAuthority [6]byte
    SubAuthorities      []uint32
}

func (s *SID) String() string {
    // Format: S-1-5-21-xxx-xxx-xxx-xxx
}

func ParseSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
    // Binary parsing of security descriptor
}
```

---

### 4.7 SID Resolver (`internal/sid/resolver.go`)

**Python Source**: `sharehound/core/SIDResolver.py` (119 lines)

```go
package sid

type SIDResolver struct {
    smbConn *smb.SMBSession
    dce     *dcerpc.Client
    cache   map[string]string
    mu      sync.RWMutex
}

func NewSIDResolver(smbConn *smb.SMBSession) (*SIDResolver, error) {
    // Initialize LSARPC binding
}

func (r *SIDResolver) ResolveSIDs(sids []string) error {
    // Use LsarLookupSids to resolve SIDs to usernames
    // Handle STATUS_SOME_NOT_MAPPED and STATUS_NONE_MAPPED
}

func (r *SIDResolver) GetSID(sid string) string {
    r.mu.RLock()
    if name, ok := r.cache[sid]; ok {
        r.mu.RUnlock()
        return name
    }
    r.mu.RUnlock()

    r.ResolveSIDs([]string{sid})

    r.mu.RLock()
    defer r.mu.RUnlock()
    if name, ok := r.cache[sid]; ok {
        return name
    }
    return sid
}
```

---

### 4.8 Collectors (`internal/collector/`)

#### 4.8.1 Share Rights (`share_rights.go`)

**Python Source**: `sharehound/collector/collect_share_rights.py` (215 lines)

```go
package collector

// AccessMaskFlags - exact same values as Python
type AccessMaskFlags uint32

const (
    DS_CREATE_CHILD           AccessMaskFlags = 0x00000001
    DS_DELETE_CHILD           AccessMaskFlags = 0x00000002
    DS_LIST_CONTENTS          AccessMaskFlags = 0x00000004
    DS_WRITE_PROPERTY_EXTENDED AccessMaskFlags = 0x00000008
    DS_READ_PROPERTY          AccessMaskFlags = 0x00000010
    DS_WRITE_PROPERTY         AccessMaskFlags = 0x00000020
    DS_DELETE_TREE            AccessMaskFlags = 0x00000040
    DS_LIST_OBJECT            AccessMaskFlags = 0x00000080
    DS_CONTROL_ACCESS         AccessMaskFlags = 0x00000100
    DELETE                    AccessMaskFlags = 0x00010000
    READ_CONTROL              AccessMaskFlags = 0x00020000
    WRITE_DAC                 AccessMaskFlags = 0x00040000
    WRITE_OWNER               AccessMaskFlags = 0x00080000
    GENERIC_ALL               AccessMaskFlags = 0x10000000
    GENERIC_EXECUTE           AccessMaskFlags = 0x20000000
    GENERIC_WRITE             AccessMaskFlags = 0x40000000
    GENERIC_READ              AccessMaskFlags = 0x80000000
)

// ShareRights maps SID to list of edge kinds
type ShareRights map[string][]string

func CollectShareRights(
    smbSession *smb.SMBSession,
    shareName string,
    rulesEvaluator *rules.Evaluator,
    log logger.LoggerInterface,
) (ShareRights, error) {
    // Map edge kinds to access mask flags
    mapRights := map[string]AccessMaskFlags{
        kinds.EdgeKindCanDsCreateChild:             DS_CREATE_CHILD,
        kinds.EdgeKindCanDsDeleteChild:             DS_DELETE_CHILD,
        kinds.EdgeKindCanDsListContents:            DS_LIST_CONTENTS,
        // ... all 17 mappings
    }

    rights := make(ShareRights)

    // Get security descriptor (with fallback to root folder)
    sd, err := smbSession.GetShareSecurityDescriptor(shareName)
    if err != nil || len(sd) == 0 {
        sd, err = smbSession.GetShareRootSecurityDescriptor(shareName)
        if err != nil {
            return rights, nil
        }
    }

    // Parse security descriptor
    secDesc, err := smb.ParseSecurityDescriptor(sd)
    if err != nil {
        return rights, err
    }

    // Process DACL
    if secDesc.Dacl == nil {
        return rights, nil
    }

    for _, ace := range secDesc.Dacl.Aces {
        if ace.AceType != smb.ACCESS_ALLOWED_ACE_TYPE {
            continue
        }

        sid := ace.SID.String()
        mask := ace.Mask

        for edgeKind, flagValue := range mapRights {
            if mask&uint32(flagValue) != 0 {
                rights[sid] = append(rights[sid], edgeKind)
            }
        }
    }

    return rights, nil
}
```

#### 4.8.2 NTFS Rights (`ntfs_rights.go`)

**Python Source**: `sharehound/collector/collect_ntfs_rights.py` (93 lines)

```go
package collector

// NTFS Access Mask Flags
const (
    NTFS_GENERIC_READ           = 0x80000000
    NTFS_GENERIC_WRITE          = 0x40000000
    NTFS_GENERIC_EXECUTE        = 0x20000000
    NTFS_GENERIC_ALL            = 0x10000000
    NTFS_MAXIMUM_ALLOWED        = 0x02000000
    NTFS_ACCESS_SYSTEM_SECURITY = 0x01000000
    NTFS_SYNCHRONIZE            = 0x00100000
    NTFS_WRITE_OWNER            = 0x00080000
    NTFS_WRITE_DACL             = 0x00040000
    NTFS_READ_CONTROL           = 0x00020000
    NTFS_DELETE                 = 0x00010000
)

func CollectNTFSRights(
    smbSession *smb.SMBSession,
    ogc *graph.OpenGraphContext,
    rulesEvaluator *rules.Evaluator,
    content os.FileInfo,
    log logger.LoggerInterface,
) (ShareRights, error) {
    mapRights := map[string]uint32{
        kinds.EdgeKindCanNTFSGenericRead:          NTFS_GENERIC_READ,
        kinds.EdgeKindCanNTFSGenericWrite:         NTFS_GENERIC_WRITE,
        kinds.EdgeKindCanNTFSGenericExecute:       NTFS_GENERIC_EXECUTE,
        kinds.EdgeKindCanNTFSGenericAll:           NTFS_GENERIC_ALL,
        kinds.EdgeKindCanNTFSMaximumAllowed:       NTFS_MAXIMUM_ALLOWED,
        kinds.EdgeKindCanNTFSAccessSystemSecurity: NTFS_ACCESS_SYSTEM_SECURITY,
        kinds.EdgeKindCanNTFSSynchronize:          NTFS_SYNCHRONIZE,
        kinds.EdgeKindCanNTFSWriteOwner:           NTFS_WRITE_OWNER,
        kinds.EdgeKindCanNTFSWriteDacl:            NTFS_WRITE_DACL,
        kinds.EdgeKindCanNTFSReadControl:          NTFS_READ_CONTROL,
        kinds.EdgeKindCanNTFSDelete:               NTFS_DELETE,
    }

    // Implementation similar to CollectShareRights
}
```

#### 4.8.3 Contents Traversal (`contents.go` and `depth_traversal.go`)

**Python Source**: `sharehound/collector/collect_contents_in_share.py` (79 lines) and `sharehound/collector/collect_contents_at_depth.py` (297 lines)

```go
package collector

type TraversalCounts struct {
    TotalFiles        int
    SkippedFiles      int
    ProcessedFiles    int
    TotalDirectories  int
    SkippedDirectories int
    ProcessedDirectories int
}

func CollectContentsInShare(
    smbSession *smb.SMBSession,
    ogc *graph.OpenGraphContext,
    rulesEvaluator *rules.Evaluator,
    workerResults *WorkerResults,
    resultsLock *sync.Mutex,
    log logger.LoggerInterface,
    timeoutEvent *atomic.Bool,
) TraversalCounts {
    return collectContentsAtDepth(
        smbSession, ogc, rulesEvaluator,
        workerResults, resultsLock, log, 0, timeoutEvent,
    )
}

func collectContentsAtDepth(
    smbSession *smb.SMBSession,
    ogc *graph.OpenGraphContext,
    rulesEvaluator *rules.Evaluator,
    workerResults *WorkerResults,
    resultsLock *sync.Mutex,
    log logger.LoggerInterface,
    depth int,
    timeoutEvent *atomic.Bool,
) TraversalCounts {
    counts := TraversalCounts{}

    // Check timeout
    if timeoutEvent != nil && timeoutEvent.Load() {
        return counts
    }

    // List contents
    contents, err := smbSession.ListContents(ogc.GetStringPathFromRoot())
    if err != nil {
        return counts
    }

    var directoriesToExplore []struct {
        node   *graph.Node
        rights ShareRights
    }

    for name, content := range contents {
        if name == "." || name == ".." {
            continue
        }

        // Get NTFS rights
        elementRights, _ := CollectNTFSRights(smbSession, ogc, rulesEvaluator, content, log)
        ogc.SetElementRights(elementRights)

        if content.IsDir() {
            // Process directory
            // Create RuleObjectDirectory, check can_explore
            // Create Directory node
            // Add to directoriesToExplore list
        } else {
            // Process file
            // Create RuleObjectFile, check can_process
            // Create File node
            // Call ogc.AddPathToGraph() if can_process
        }

        ogc.ClearElement()
    }

    // BFS: Process next level directories
    for _, dir := range directoriesToExplore {
        if timeoutEvent != nil && timeoutEvent.Load() {
            break
        }

        ogc.PushPath(dir.node, dir.rights)
        subCounts := collectContentsAtDepth(
            smbSession, ogc, rulesEvaluator,
            workerResults, resultsLock, log, depth+1, timeoutEvent,
        )
        counts.Add(subCounts)
        ogc.PopPath()
    }

    return counts
}
```

---

### 4.9 Graph Context (`internal/graph/`)

**Python Source**: `sharehound/collector/opengraph_context.py` (465 lines)

```go
package graph

type OpenGraphContext struct {
    graph            *OpenGraph
    host             *Node
    share            *Node
    shareRights      ShareRights
    path             []struct {
        node   *Node
        rights ShareRights
    }
    element          *Node
    elementRights    ShareRights
    logger           logger.LoggerInterface
    totalEdgesCreated int
}

func NewOpenGraphContext(graph *OpenGraph, log logger.LoggerInterface) *OpenGraphContext {
    return &OpenGraphContext{
        graph:  graph,
        logger: log,
        path:   make([]struct{node *Node; rights ShareRights}, 0),
    }
}

func (c *OpenGraphContext) AddPathToGraph() {
    // Add host node with HostsNetworkShare edge to BloodHound Computer
    // Add share node with HasNetworkShare edge
    // Add share rights edges
    // Add directory path with Contains edges
    // Add element (file/directory) with Contains edge
    // Add element rights edges
}

func (c *OpenGraphContext) AddRightsToGraph(elementID string, rights ShareRights, elementType string) {
    for sid, edgeKinds := range rights {
        for _, edgeKind := range edgeKinds {
            c.graph.AddEdge(&Edge{
                StartNode: sid,
                EndNode:   elementID,
                Kind:      edgeKind,
            })
            c.totalEdgesCreated++
        }
    }
}

// Getters and setters
func (c *OpenGraphContext) SetHost(host *Node) { c.host = host }
func (c *OpenGraphContext) SetShare(share *Node) { c.share = share }
func (c *OpenGraphContext) SetShareRights(rights ShareRights) { c.shareRights = rights }
func (c *OpenGraphContext) PushPath(node *Node, rights ShareRights) { /* ... */ }
func (c *OpenGraphContext) PopPath() *Node { /* ... */ }
func (c *OpenGraphContext) SetElement(element *Node) { c.element = element }
func (c *OpenGraphContext) GetStringPathFromRoot() string { /* ... */ }
// ... etc
```

---

### 4.10 Rules Engine (`internal/rules/`)

**Python Source**: Uses `shareql` library

The ShareQL DSL needs to be reimplemented. Key grammar:

```
rule := action condition? | DEFAULT ":" behavior
action := "ALLOW" | "DENY"
behavior := "ALLOW" | "DENY"
condition := ("EXPLORATION" | "PROCESSING") "IF" expression
expression := term (("AND" | "OR") term)*
term := field comparator value | "NOT" term | "(" expression ")"
field := "SHARE.NAME" | "SHARE.DESCRIPTION" | "SHARE.HIDDEN" |
         "FILE.NAME" | "FILE.PATH" | "FILE.SIZE" | "FILE.EXTENSION" |
         "DIR.NAME" | "DIR.PATH" | "DEPTH"
comparator := "=" | "!=" | "<" | ">" | "<=" | ">=" | "IN" | "NOT IN" | "MATCHES"
value := STRING | NUMBER | BOOLEAN | LIST
```

```go
package rules

// Rule represents a parsed ShareQL rule
type Rule struct {
    IsDefault    bool
    DefaultBehavior string  // "ALLOW" or "DENY"
    Action       string     // "ALLOW" or "DENY"
    RuleType     string     // "EXPLORATION" or "PROCESSING" or ""
    Condition    Expression
}

type Expression interface {
    Evaluate(ctx *EvaluationContext) bool
}

type EvaluationContext struct {
    Share     *RuleObjectShare
    File      *RuleObjectFile
    Directory *RuleObjectDirectory
    Depth     int
}

type RulesEvaluator struct {
    rules   []Rule
    context *EvaluationContext
}

func (e *RulesEvaluator) CanExplore(obj interface{}) bool {
    // Evaluate EXPLORATION rules
}

func (e *RulesEvaluator) CanProcess(obj interface{}) bool {
    // Evaluate PROCESSING rules
}

// Rule objects
type RuleObjectShare struct {
    Name        string
    Description string
    Hidden      bool
}

type RuleObjectFile struct {
    Name       string
    Path       string
    Size       int64
    Extension  string
    ModifiedAt time.Time
    CreatedAt  time.Time
}

type RuleObjectDirectory struct {
    Name       string
    Path       string
    ModifiedAt time.Time
    CreatedAt  time.Time
}
```

---

### 4.11 Worker (`internal/worker/`)

**Python Source**: `sharehound/worker.py` (609 lines)

```go
package worker

type ConnectionPool struct {
    maxConnectionsPerHost int
    connections          map[string][]*smb.SMBSession
    semaphores           map[string]*semaphore.Weighted
    mu                   sync.Mutex
}

func (p *ConnectionPool) GetConnection(
    host, remoteName string,
    options *Options,
    cfg *config.Config,
    log *logger.Logger,
) (*smb.SMBSession, error) {
    // Reuse existing or create new connection
}

func (p *ConnectionPool) ReturnConnection(host string, conn *smb.SMBSession) {
    // Return to pool or close if full
}

type WorkerResults struct {
    Success    int64
    Errors     int64
    Tasks      TaskCounts
    Shares     ItemCounts
    Files      ItemCounts
    Directories ItemCounts
}

type TaskCounts struct {
    Pending  int64
    Total    int64
    Finished int64
}

type ItemCounts struct {
    Total     int64
    Processed int64
    Skipped   int64
    Pending   int64
}

func ProcessShareTask(
    shareName string,
    shareData *smb.ShareInfo,
    host, remoteName string,
    options *Options,
    cfg *config.Config,
    graph *graph.OpenGraph,
    parsedRules []rules.Rule,
    connectionPool *ConnectionPool,
    hostSemaphore *semaphore.Weighted,
    workerResults *WorkerResults,
    resultsLock *sync.Mutex,
    log *logger.Logger,
    timeoutEvent *atomic.Bool,
) (counts TraversalCounts) {
    // Process single share with retry logic
}

func MultithreadedShareWorker(
    options *Options,
    cfg *config.Config,
    graph *graph.OpenGraph,
    target Target,
    parsedRules []rules.Rule,
    workerResults *WorkerResults,
    resultsLock *sync.Mutex,
    maxWorkersPerHost, globalMaxWorkers int,
) {
    // Main worker function using goroutines
}
```

---

### 4.12 Targets (`internal/targets/loader.go`)

**Python Source**: `sharehound/targets.py` (151 lines)

```go
package targets

type Target struct {
    Type  string // "ipv4", "ipv6", "fqdn", "cidr"
    Value string
}

func LoadTargets(options *Options, cfg *config.Config, log *logger.Logger) ([]Target, error) {
    var targets []string

    // Load from file
    if options.TargetsFile != "" {
        targets = append(targets, loadFromFile(options.TargetsFile)...)
    }

    // Load from CLI
    targets = append(targets, options.Targets...)

    // Load from AD if no explicit targets
    if len(targets) == 0 && options.AuthDCIP != "" {
        computers, _ := getComputersFromDomain(options)
        targets = append(targets, computers...)
        servers, _ := getServersFromDomain(options)
        targets = append(targets, servers...)
    }

    // Load subnets if requested
    if options.Subnets {
        subnets, _ := getSubnets(options)
        targets = append(targets, subnets...)
    }

    // Parse and classify targets
    var finalTargets []Target
    for _, t := range uniqueSorted(targets) {
        if isIPv4CIDR(t) {
            for _, ip := range expandCIDR(t) {
                finalTargets = append(finalTargets, Target{"ipv4", ip})
            }
        } else if isIPv4Addr(t) {
            finalTargets = append(finalTargets, Target{"ipv4", t})
        } else if isIPv6Addr(t) {
            finalTargets = append(finalTargets, Target{"ipv6", t})
        } else if isFQDN(t) {
            finalTargets = append(finalTargets, Target{"fqdn", t})
        }
    }

    return uniqueSorted(finalTargets), nil
}
```

---

## 5. Node Types (Feature Parity)

**Python Source**: `sharehound/kinds.py`

All node kinds must be exactly the same:

```go
package kinds

// Base node kind
const NodeKindNetworkShareBase = "NetworkShareBase"

// Host and share node kinds
const NodeKindNetworkShareHost = "NetworkShareHost"
const NodeKindNetworkShareDFS = "NetworkShareDFS"
const NodeKindNetworkShareSMB = "NetworkShareSMB"

// Content node kinds
const NodeKindFile = "File"
const NodeKindDirectory = "Directory"

// Principal node kinds (referenced from AD)
const NodeKindPrincipal = "Principal"
const NodeKindUser = "User"
const NodeKindGroup = "Group"
```

---

## 6. Edge Types (Feature Parity)

All edge kinds must be exactly the same:

```go
package kinds

// Containment edges
const EdgeKindHasNetworkShare = "HasNetworkShare"
const EdgeKindHostsNetworkShare = "HostsNetworkShare"
const EdgeKindContains = "Contains"

// Share-level permission edges
const EdgeKindCanGenericExecute = "CanGenericExecute"
const EdgeKindCanGenericWrite = "CanGenericWrite"
const EdgeKindCanGenericRead = "CanGenericRead"
const EdgeKindCanGenericAll = "CanGenericAll"

const EdgeKindCanDsCreateChild = "CanDsCreateChild"
const EdgeKindCanDsDeleteChild = "CanDsDeleteChild"
const EdgeKindCanDsListContents = "CanDsListContents"
const EdgeKindCanDsWriteExtendedProperties = "CanDsWriteExtendedProperties"
const EdgeKindCanDsReadProperty = "CanDsReadProperty"
const EdgeKindCanDsWriteProperty = "CanDsWriteProperty"
const EdgeKindCanDsDeleteTree = "CanDsDeleteTree"
const EdgeKindCanDsListObject = "CanDsListObject"
const EdgeKindCanDsControlAccess = "CanDsControlAccess"

const EdgeKindCanDelete = "CanDelete"
const EdgeKindCanReadControl = "CanReadControl"
const EdgeKindCanWriteDacl = "CanWriteDacl"
const EdgeKindCanWriteOwner = "CanWriteOwner"

// NTFS-level permission edges
const EdgeKindCanNTFSGenericRead = "CanNTFSGenericRead"
const EdgeKindCanNTFSGenericWrite = "CanNTFSGenericWrite"
const EdgeKindCanNTFSGenericExecute = "CanNTFSGenericExecute"
const EdgeKindCanNTFSGenericAll = "CanNTFSGenericAll"
const EdgeKindCanNTFSMaximumAllowed = "CanNTFSMaximumAllowed"
const EdgeKindCanNTFSAccessSystemSecurity = "CanNTFSAccessSystemSecurity"
const EdgeKindCanNTFSSynchronize = "CanNTFSSynchronize"
const EdgeKindCanNTFSWriteOwner = "CanNTFSWriteOwner"
const EdgeKindCanNTFSWriteDacl = "CanNTFSWriteDacl"
const EdgeKindCanNTFSReadControl = "CanNTFSReadControl"
const EdgeKindCanNTFSDelete = "CanNTFSDelete"
```

---

## 7. Output Format

### BloodHound OpenGraph JSON Structure

The output must be identical to the Python version:

```json
{
  "data": [
    {
      "id": "192.168.1.100",
      "kind": "NetworkShareHost",
      "properties": {
        "name": "192.168.1.100"
      }
    },
    {
      "id": "\\\\192.168.1.100\\share$\\",
      "kind": "NetworkShareSMB",
      "properties": {
        "displayName": "share$",
        "description": "",
        "hidden": true
      }
    },
    {
      "id": "FILE:\\\\192.168.1.100\\share$\\folder\\file.txt",
      "kind": "File",
      "properties": {
        "name": "file.txt",
        "Path": "folder\\file.txt",
        "UNCPath": "\\\\192.168.1.100\\share$\\folder\\file.txt",
        "fileSize": 1024,
        "createdAt": "2025-01-01T12:00:00Z",
        "modifiedAt": "2025-01-15T08:30:00Z",
        "extension": ".txt"
      }
    }
  ],
  "edges": [
    {
      "start": "192.168.1.100",
      "end": "\\\\192.168.1.100\\share$\\",
      "kind": "HasNetworkShare"
    },
    {
      "start": "S-1-5-21-xxx-xxx-xxx-1001",
      "end": "\\\\192.168.1.100\\share$\\",
      "kind": "CanGenericRead"
    }
  ]
}
```

---

## 8. Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)

1. Project scaffolding and Go modules
2. Configuration and credentials
3. Logger (both main and task logger)
4. Basic CLI argument parsing
5. Utility functions (DNS, network, filesize, hash parsing)

### Phase 2: SMB Implementation (Week 3-5)

1. SMB session management with dialect fallback
2. SMB error classification
3. Security descriptor parsing
4. Share enumeration via SRVSVC
5. Directory listing

### Phase 3: DCERPC and SID Resolution (Week 6-7)

1. LSARPC binding for SID resolution
2. SRVSVC for detailed share info
3. Remote registry access for share security descriptors
4. SID caching

### Phase 4: Graph and Collectors (Week 8-9)

1. Node and edge types
2. OpenGraph structure
3. OpenGraphContext
4. Share rights collector
5. NTFS rights collector
6. Contents traversal (BFS)

### Phase 5: Rules Engine (Week 10-11)

1. ShareQL grammar definition
2. Parser implementation
3. Expression evaluator
4. Rule objects (Share, File, Directory)

### Phase 6: Worker and Concurrency (Week 12-13)

1. Connection pool
2. Worker goroutines
3. Share task processing
4. Timeout handling
5. Progress UI

### Phase 7: Target Loading and AD Integration (Week 14)

1. Target file loading
2. LDAP queries for computers/servers
3. Subnet enumeration
4. CIDR expansion

### Phase 8: Testing and Polish (Week 15-16)

1. Unit tests for all modules
2. Integration tests
3. Cross-platform testing
4. Documentation
5. Build and release automation

---

## 9. Testing Strategy

### Unit Tests

```go
// Example: security_descriptor_test.go
func TestParseSecurityDescriptor(t *testing.T) {
    // Test binary parsing with known good data
}

func TestSIDFormatCanonical(t *testing.T) {
    tests := []struct {
        input    []byte
        expected string
    }{
        {[]byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, ...}, "S-1-5-21-..."},
    }
    // ...
}
```

### Integration Tests

1. Run against test SMB shares (Samba)
2. Compare output JSON with Python version
3. Verify node and edge counts match
4. Test authentication methods (NTLM, Kerberos, pass-the-hash)

### Compatibility Tests

1. Run both Python and Go versions against same targets
2. Diff output JSON files
3. Verify import into BloodHound works correctly

---

## 10. Risk Assessment

### High Risk

| Risk | Mitigation |
|------|------------|
| SMB library limitations | May need to contribute to go-smb2 or write custom code |
| DCERPC complexity | Consider using go-msrpc or porting relevant impacket code |
| Security descriptor parsing edge cases | Extensive testing with real-world data |

### Medium Risk

| Risk | Mitigation |
|------|------------|
| ShareQL parser differences | Thorough grammar testing |
| Concurrency bugs | Use race detector, careful locking |
| Performance differences | Benchmark and optimize |

### Low Risk

| Risk | Mitigation |
|------|------------|
| CLI flag differences | Automated testing of flag parsing |
| JSON output format | Schema validation |

---

## Appendix A: File-to-File Mapping

| Python File | Go File(s) | Lines (Est.) |
|-------------|------------|--------------|
| `__main__.py` | `cmd/sharehound/main.go` | 400 |
| `core/Config.py` | `internal/config/config.go` | 60 |
| `core/Credentials.py` | `internal/credentials/credentials.go` | 120 |
| `core/Logger.py` | `internal/logger/logger.go`, `tasklogger.go` | 350 |
| `core/SMBSession.py` | `internal/smb/*.go` | 1,500 |
| `core/SIDResolver.py` | `internal/sid/resolver.go` | 150 |
| `collector/*.py` | `internal/collector/*.go` | 800 |
| `collector/opengraph_context.py` | `internal/graph/context.go` | 500 |
| `kinds.py` | `pkg/kinds/kinds.go` | 100 |
| `worker.py` | `internal/worker/*.go` | 700 |
| `targets.py` | `internal/targets/loader.go` | 200 |
| `status.py` | `internal/status/progress.go` | 250 |
| `utils/*.py` | `internal/utils/*.go` | 400 |
| *Rules engine* | `internal/rules/*.go` | 600 |
| *DCERPC* | `internal/dcerpc/*.go` | 500 |
| **Total** | | **~6,600** |

---

## Appendix B: Quick Reference - Access Mask Values

### Share-Level Access Mask

```
DS_CREATE_CHILD              = 0x00000001
DS_DELETE_CHILD              = 0x00000002
DS_LIST_CONTENTS             = 0x00000004
DS_WRITE_PROPERTY_EXTENDED   = 0x00000008
DS_READ_PROPERTY             = 0x00000010
DS_WRITE_PROPERTY            = 0x00000020
DS_DELETE_TREE               = 0x00000040
DS_LIST_OBJECT               = 0x00000080
DS_CONTROL_ACCESS            = 0x00000100
DELETE                       = 0x00010000
READ_CONTROL                 = 0x00020000
WRITE_DAC                    = 0x00040000
WRITE_OWNER                  = 0x00080000
GENERIC_ALL                  = 0x10000000
GENERIC_EXECUTE              = 0x20000000
GENERIC_WRITE                = 0x40000000
GENERIC_READ                 = 0x80000000
```

### NTFS-Level Access Mask

```
GENERIC_READ                 = 0x80000000
GENERIC_WRITE                = 0x40000000
GENERIC_EXECUTE              = 0x20000000
GENERIC_ALL                  = 0x10000000
MAXIMUM_ALLOWED              = 0x02000000
ACCESS_SYSTEM_SECURITY       = 0x01000000
SYNCHRONIZE                  = 0x00100000
WRITE_OWNER                  = 0x00080000
WRITE_DACL                   = 0x00040000
READ_CONTROL                 = 0x00020000
DELETE                       = 0x00010000
```

---

## Appendix C: ShareQL Grammar

```ebnf
ruleset     = rule*
rule        = default_rule | action_rule
default_rule = "DEFAULT" ":" behavior
action_rule = action [scope] ["IF" condition]

action      = "ALLOW" | "DENY"
behavior    = "ALLOW" | "DENY"
scope       = "EXPLORATION" | "PROCESSING"

condition   = or_expr
or_expr     = and_expr ("OR" and_expr)*
and_expr    = unary_expr ("AND" unary_expr)*
unary_expr  = "NOT" unary_expr | primary
primary     = comparison | "(" condition ")"

comparison  = field comparator value
field       = share_field | file_field | dir_field | "DEPTH"
share_field = "SHARE" "." ("NAME" | "DESCRIPTION" | "HIDDEN")
file_field  = "FILE" "." ("NAME" | "PATH" | "SIZE" | "EXTENSION")
dir_field   = "DIR" "." ("NAME" | "PATH")

comparator  = "=" | "!=" | "<" | ">" | "<=" | ">=" | "IN" | "NOT" "IN" | "MATCHES"
value       = STRING | NUMBER | BOOLEAN | list
list        = "[" [value ("," value)*] "]"

STRING      = "'" [^']* "'" | '"' [^"]* '"'
NUMBER      = [0-9]+
BOOLEAN     = "TRUE" | "FALSE"
```

---

This plan provides a complete roadmap for porting ShareHound to Go with feature parity. The key success factors are:

1. **Exact same CLI interface** - All flags and options must match
2. **Exact same output format** - JSON structure must be identical
3. **Exact same node/edge types** - All kinds must match exactly
4. **Exact same access mask mappings** - Permission edges must be identical
5. **Equivalent SMB/DCERPC capabilities** - Authentication, share enumeration, security descriptors
