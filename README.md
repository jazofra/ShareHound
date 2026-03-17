# ShareHound

A tool that maps network share access rights into BloodHound OpenGraph format for security analysis.

**Original project by Remi Gascou ([@podalirius_](https://twitter.com/podalirius_)) @ SpecterOps**

**Go implementation by Javier Azofra @ Siemens Healthineers**

## Features

- Enumerate SMB shares and their permissions across network hosts
- Support for both share-level and NTFS-level access rights
- BloodHound OpenGraph JSON output format
- **ZIP compression** for large outputs (handles millions of edges)
- ShareQL rule engine for filtering what gets explored/processed
- Multithreaded processing with connection pooling
- NTLM, Kerberos, and pass-the-hash authentication
- CIDR range and target file support
- **Resumable scans** with checkpoint support
- Cross-platform builds (Linux, Windows, macOS)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/jazofra/sharehound
cd sharehound

# Build for current platform
go build -o sharehound.exe .\cmd\sharehound\
```

### Pre-built Binaries

Download from the [Releases](https://github.com/specterops/sharehound/releases) page.

## Usage

### Basic Examples

```bash
# Basic usage with password authentication
./sharehound --target 192.168.1.100 \
    --auth-domain CORP \
    --auth-dc-ip 192.168.1.1 \
    --auth-user administrator \
    --auth-password 'P@ssw0rd'

# With pass-the-hash
./sharehound --target 192.168.1.100 \
    --auth-domain CORP \
    --auth-dc-ip 192.168.1.1 \
    --auth-user administrator \
    --auth-hashes 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'

# Scan a CIDR range with targets file (ZIP compressed output)
./sharehound --target 192.168.1.0/24 \
    --targets-file additional_hosts.txt \
    --auth-domain CORP \
    --auth-dc-ip 192.168.1.1 \
    --auth-user administrator \
    --auth-password 'P@ssw0rd' \
    --output results.zip

# With checkpoint for resumable scans
./sharehound --target 192.168.1.0/24 \
    --auth-domain CORP \
    --auth-dc-ip 192.168.1.1 \
    --auth-user administrator \
    --auth-password 'P@ssw0rd' \
    --checkpoint scan.checkpoint

# Resume an interrupted scan
./sharehound --checkpoint scan.checkpoint --resume

# With Kerberos authentication
./sharehound --target dc01.corp.local \
    --auth-domain CORP \
    --auth-user administrator \
    --use-kerberos \
    --kdc-host dc01.corp.local

# With custom rules
./sharehound --target 192.168.1.0/24 \
    --auth-domain CORP \
    --auth-dc-ip 192.168.1.1 \
    --auth-user administrator \
    --auth-password 'P@ssw0rd' \
    --rules-file custom_rules.txt
```

## Command Line Options

### Target Selection
| Flag | Description |
|------|-------------|
| `--target` | Target IP, FQDN or CIDR (can be specified multiple times) |
| `-f, --targets-file` | Path to file containing targets (one per line) |
| `--subnets` | Auto-enumerate all domain subnets via LDAP |

### Authentication
| Flag | Description |
|------|-------------|
| `--auth-domain` | Windows domain to authenticate to |
| `--auth-dc-ip` | IP of the domain controller (for SID resolution) |
| `--auth-user` | Username of the domain account |
| `--auth-password` | Password of the domain account |
| `--auth-hashes` | LM:NT hashes for pass-the-hash |
| `--auth-key` | Kerberos key for authentication |
| `-k, --use-kerberos` | Use Kerberos authentication |
| `--kdc-host` | KDC host for Kerberos authentication |
| `--ldaps` | Use LDAPS instead of LDAP |

### Share Exploration
| Flag | Description | Default |
|------|-------------|---------|
| `--share` | Specific share to enumerate (default: all shares) | all |
| `--depth` | Maximum depth to traverse directories (0 = unlimited) | 0 |
| `--include-common-shares` | Include C$, ADMIN$, IPC$, PRINT$ | false |

### Performance
| Flag | Description | Default |
|------|-------------|---------|
| `--threads` | Number of concurrent hosts to process | NumCPU × 8 |
| `--max-workers-per-host` | Maximum concurrent shares per host | 8 |
| `--global-max-workers` | Global maximum workers | 200 |
| `-t, --timeout` | Timeout in seconds for network operations | 2.5 |
| `--host-timeout` | Maximum time in minutes per host (0 = no limit) | 0 |

### Output
| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output file path (use .zip for compression) | opengraph.zip |
| `--logfile` | Log file to write to | - |
| `-v, --verbose` | Verbose mode | false |
| `--debug` | Debug mode | false |
| `--no-colors` | Disable ANSI escape codes | false |

### Checkpoint/Resume
| Flag | Description | Default |
|------|-------------|---------|
| `--checkpoint` | Checkpoint file for resumable scans | - |
| `--checkpoint-interval` | Checkpoint save interval in seconds | 60 |
| `--resume` | Resume from existing checkpoint file | false |

### Rules
| Flag | Description |
|------|-------------|
| `-r, --rules-file` | Path to file containing rules (can be specified multiple times) |
| `--rule-string` | Rule string (can be specified multiple times) |

### Other
| Flag | Description |
|------|-------------|
| `--advertised-name` | Advertised name of the client |
| `-n, --nameserver` | Nameserver for DNS queries |

## Performance Optimization

### Threading Model

ShareHound uses a two-level concurrency model:

```
┌─────────────────────────────────────────────────────────────────┐
│                         Main Process                             │
│  --threads (default: NumCPU * 8)                                │
│  Controls: Maximum concurrent HOSTS being processed             │
├─────────────────────────────────────────────────────────────────┤
│  Host 1              │  Host 2              │  Host 3       │...│
│  ┌─────────────────┐ │  ┌─────────────────┐ │  ┌──────────┐ │   │
│  │ Share A         │ │  │ Share X         │ │  │ Share P  │ │   │
│  │ Share B         │ │  │ Share Y         │ │  │ Share Q  │ │   │
│  │ Share C         │ │  │ ...             │ │  │ ...      │ │   │
│  └─────────────────┘ │  └─────────────────┘ │  └──────────┘ │   │
│  --max-workers-per-  │                      │               │   │
│  host (default: 8)   │                      │               │   │
└─────────────────────────────────────────────────────────────────┘
```

| Flag | Default | Description |
|------|---------|-------------|
| `--threads` | `NumCPU * 8` | Maximum concurrent hosts being processed |
| `--max-workers-per-host` | `8` | Maximum concurrent shares per host |
| `--host-timeout` | `0` (disabled) | Minutes before forcefully skipping a stuck host |
| `--timeout` | `2.5` | Seconds for individual network operations |

### Host Timeout Enforcement

When `--host-timeout` is set, ShareHound will **forcefully terminate** connections to hosts that exceed the time limit:

1. A timer fires after the specified minutes
2. All active TCP connections to the host are forcefully closed (immediate deadline set)
3. Any blocking SMB operations (ReadDir, Mount, etc.) fail immediately
4. All data collected up to that point is **preserved** in the graph
5. The host is marked as processed and scanning continues

This is essential for large scans where some hosts may be unresponsive or have extremely large shares.

### Recommended Settings

**Standard workstation (8 cores, 16GB RAM):**
```bash
./sharehound \
  --threads 64 \
  --max-workers-per-host 4 \
  --host-timeout 5 \
  --timeout 3 \
  --auth-dc-ip <DC_IP> \
  --auth-domain <DOMAIN> \
  --auth-user <USER> \
  --auth-password <PASS>
```

**Powerful server (32+ cores, 64GB+ RAM):**
```bash
./sharehound \
  --threads 256 \
  --max-workers-per-host 8 \
  --host-timeout 3 \
  --timeout 2 \
  --auth-dc-ip <DC_IP> \
  --auth-domain <DOMAIN> \
  --auth-user <USER> \
  --auth-password <PASS>
```

**Large enterprise scan (60,000+ hosts):**
```bash
./sharehound \
  --threads 128 \
  --max-workers-per-host 4 \
  --host-timeout 3 \
  --timeout 2 \
  --depth 5 \
  --checkpoint sharehound.checkpoint \
  --checkpoint-interval 60 \
  -o results.zip \
  --auth-dc-ip <DC_IP> \
  --auth-domain <DOMAIN> \
  --auth-user <USER> \
  --auth-password <PASS>
```

### Performance Tips

1. **Always use `--host-timeout`** for large scans (2-5 minutes recommended)
2. **Lower `--timeout`** to 1.5-2.5 seconds - slow hosts will be skipped faster
3. **Increase `--threads`** - scanning is I/O bound, more threads = better throughput
4. **Use `--depth`** to limit directory traversal if you don't need deep scans
5. **Enable checkpointing** for large scans to resume if interrupted
6. **Use ZIP output** (default) - handles millions of edges without memory issues

### Target Count Explanation

When scanning from Active Directory, you may notice fewer hosts targeted than computers found:

```
Found 70,870 computers in Active Directory
Found 5,156 servers in Active Directory
Targeting 66,014 hosts
```

This is because:
- **Servers overlap with computers** - all servers are also computer objects
- **Deduplication** removes duplicate entries
- **Validation** filters out entries without valid DNS hostnames/FQDNs

## Output Format

The output is a BloodHound OpenGraph JSON file that can be imported into BloodHound Enterprise or Community Edition.

### BloodHound Schema Compliance

The output follows the [BloodHound OpenGraph Schema](https://bloodhound.specterops.io/opengraph/schema):

- **Nodes:** `id` (required), `kinds` (array), `properties` (object)
- **Edges:** `start` (object with `value`), `end` (object with `value`), `kind` (string), `properties` (object)
- **Metadata:** `source_kind` for attribution

### ZIP Compression

By default, output is compressed as a ZIP archive (`opengraph.zip`) containing the JSON file. This provides:
- **~90% size reduction** for large scans
- **Streaming export** - handles millions of edges without memory issues
- Compatible with BloodHound's ZIP import

To output uncompressed JSON, use a `.json` extension:
```bash
./sharehound --target ... -o output.json
```

### Node Types (9 total)

| Node Type | Description |
|-----------|-------------|
| `NetworkShareBase` | Base type for all network share nodes |
| `NetworkShareHost` | An SMB server/host |
| `NetworkShareSMB` | An SMB share |
| `NetworkShareDFS` | A DFS share |
| `File` | A file on a share (`depth`, `fileSize`, `extension`, timestamps) |
| `Directory` | A directory on a share (`depth`, timestamps) |
| `Principal` | A security principal (generic) |
| `User` | A user principal |
| `Group` | A group principal |

### Edge Types (42 total)

#### Containment Edges (3)
| Edge Type | Description |
|-----------|-------------|
| `HostsNetworkShare` | Computer to NetworkShareHost relationship |
| `HasNetworkShare` | Host to Share relationship |
| `Contains` | Parent to Child (directory to file/subdirectory) |

#### Share-Level Permission Edges (17)

**Generic Rights:**
- `CanGenericRead` - Generic read access
- `CanGenericWrite` - Generic write access
- `CanGenericExecute` - Generic execute access
- `CanGenericAll` - Full control

**Directory Service Rights:**
- `CanDsCreateChild` - Create child objects
- `CanDsDeleteChild` - Delete child objects
- `CanDsListContents` - List contents
- `CanDsWriteExtendedProperties` - Write extended properties
- `CanDsReadProperty` - Read properties
- `CanDsWriteProperty` - Write properties
- `CanDsDeleteTree` - Delete tree
- `CanDsListObject` - List objects
- `CanDsControlAccess` - Control access

**Standard Rights:**
- `CanDelete` - Delete permission
- `CanReadControl` - Read security descriptor
- `CanWriteDacl` - Modify DACL
- `CanWriteOwner` - Take ownership

#### NTFS-Level Permission Edges (19)

**Generic Rights (defensive fallback — rarely stored in on-disk ACEs; Windows maps these to specific rights before writing):**
- `CanNTFSGenericRead` - GENERIC_READ (0x80000000)
- `CanNTFSGenericWrite` - GENERIC_WRITE (0x40000000)
- `CanNTFSGenericExecute` - GENERIC_EXECUTE (0x20000000)
- `CanNTFSGenericAll` - GENERIC_ALL (0x10000000)

**Standard Rights:**
- `CanNTFSAccessSystemSecurity` - ACCESS_SYSTEM_SECURITY (0x01000000) — read/modify SACL
- `CanNTFSSynchronize` - SYNCHRONIZE (0x00100000)
- `CanNTFSWriteOwner` - WRITE_OWNER (0x00080000) — take ownership
- `CanNTFSWriteDacl` - WRITE_DAC (0x00040000) — change permissions
- `CanNTFSReadControl` - READ_CONTROL (0x00020000) — read security descriptor
- `CanNTFSDelete` - DELETE (0x00010000)

**Object-Specific (File/Directory) Rights:**
- `CanNTFSReadData` - Read file contents / list directory (FILE_READ_DATA)
- `CanNTFSWriteData` - Write file data / create files in directory (FILE_WRITE_DATA)
- `CanNTFSAppendData` - Append data / create subdirectories (FILE_APPEND_DATA)
- `CanNTFSReadEA` - Read extended attributes (FILE_READ_EA)
- `CanNTFSWriteEA` - Write extended attributes (FILE_WRITE_EA)
- `CanNTFSExecute` - Execute file / traverse directory (FILE_EXECUTE)
- `CanNTFSDeleteChild` - Delete child objects in directory (FILE_DELETE_CHILD)
- `CanNTFSReadAttributes` - Read basic attributes (FILE_READ_ATTRIBUTES)
- `CanNTFSWriteAttributes` - Write basic attributes (FILE_WRITE_ATTRIBUTES)

#### Effective Access Edges (3)

Derived edges emitted when the **same SID** holds matching generic rights at **both**
the share level and the NTFS level. Windows enforces both DACLs when a file is accessed
over SMB; effective access is their intersection.

| Edge Type | Share right required | NTFS right required |
|-----------|---------------------|---------------------|
| `CanEffectiveRead` | `CanGenericRead` or `CanGenericAll` | `CanNTFSGenericRead`, `CanNTFSReadData`, or `CanNTFSGenericAll` |
| `CanEffectiveWrite` | `CanGenericWrite` or `CanGenericAll` | `CanNTFSGenericWrite`, `CanNTFSWriteData`, or `CanNTFSGenericAll` |
| `CanEffectiveExecute` | `CanGenericExecute` or `CanGenericAll` | `CanNTFSGenericExecute`, `CanNTFSExecute`, or `CanNTFSGenericAll` |

> **Limitation:** effective edges are per-SID only. If a user inherits share read
> through a group SID but holds NTFS read under their personal SID (or vice versa), no
> effective edge is emitted. BloodHound's AD graph can close this gap at query time via
> group membership traversal.

### How Edges Are Built

This section describes the pipeline that turns raw Windows security descriptors into
BloodHound graph edges.

#### 1. Binary Security Descriptor Parsing (`internal/smb/security_descriptor.go`, `internal/smb/sid.go`)

When ShareHound opens a file, directory, or queries a share, it calls
`QuerySecurityDescriptor` over SMB to retrieve the raw binary Windows Security Descriptor.
Three functions parse it:

- **`ParseSecurityDescriptor`** — reads the header (revision, control flags, byte offsets)
  and conditionally parses the Owner SID, Group SID, SACL, and DACL.
- **`ParseACL`** — reads the ACL header (revision, size, ACE count) and iterates through
  each ACE at the correct byte offset.
- **`ParseACE`** — extracts each entry: type (byte 0), flags (byte 1), size (bytes 2–3),
  access mask (`uint32` at offset 4), SID (starting at offset 8). Only
  `ACCESS_ALLOWED` ACEs (type `0x00`) produce edges.

SIDs are parsed by `ParseSID` (`internal/smb/sid.go`) — it reads the revision,
sub-authority count, identifier authority, and variable-length sub-authorities — then
formatted as the canonical `S-R-I-SA1-SA2-...-SAn` string used as the edge source.

#### 2. Access Mask → Edge Kinds (`internal/smb/access_mask.go`)

The parsed `uint32` access mask is converted to a slice of edge kind strings by
bitwise-ANDing it against every known permission flag. A single ACE with multiple bits
set produces multiple edges. Two mappings are used:

- **`NTFSRightsMapping`** — applied to file and directory ACEs; produces the
  `CanNTFS*` edge kinds listed above.
- **`ShareRightsMapping`** — applied to share-level ACEs (retrieved via SRVSVC RPC);
  produces the generic and DS-rights edge kinds listed above.

Functions `GetNTFSRightsForMask(mask)` and `GetShareRightsForMask(mask)` implement this
logic and return all matching edge kinds for a given mask.

#### 3. Rights Collection (`internal/collector/`)

| Collector | Source | Fallback |
|-----------|--------|----------|
| `share_rights.go` — `CollectShareRights` | SRVSVC RPC share security descriptor | Root folder NTFS SD |
| `ntfs_rights.go` — `CollectNTFSRights` | `QuerySecurityDescriptor` per file/dir | — |

Both return a `ShareRights` map (`map[string][]string`, i.e. SID → edge kinds).

#### 4. Graph Edge Creation (`internal/graph/context.go`)

`AddRightsToGraph(elementID, rights, elementType, nodeKind)` converts the `ShareRights`
map into actual graph edges:

1. For each SID in the map, non-domain SIDs (well-known / BUILTIN such as `S-1-1-0` or
   `S-1-5-32-545`) are prefixed with the domain FQDN so BloodHound can resolve them
   (e.g. `CORP.COM-S-1-1-0`). Domain-relative SIDs (`S-1-5-21-*`) are used as-is.
2. For each edge kind in the SID's list, an edge is created:
   `NewEdge(SID, elementID, edgeKind)` with `SetEndKind(nodeKind)` so BloodHound
   knows the type of the target node.

`AddPathToGraph` calls `AddRightsToGraph` at three levels: the share node (share-level
rights), each directory in the traversal path (NTFS rights), and the leaf file or
directory element (NTFS rights).

#### Data Flow

```
SMB QuerySecurityDescriptor (binary)
  └─ ParseSecurityDescriptor / ParseACL / ParseACE
        └─ GetNTFSRightsForMask(ace.Mask)  →  []edgeKind
              └─ ShareRights map { SID → []edgeKind }
                    └─ AddRightsToGraph()
                          └─ NewEdge(SID, nodeID, edgeKind)
                                SetEndKind(nodeKind)
                                → BloodHound OpenGraph JSON
```

## ShareQL Rules

ShareQL is a domain-specific language for filtering what gets explored and processed. Rules are evaluated in order, and the first matching rule determines the action.

### Syntax

```
DEFAULT: ALLOW|DENY
ALLOW|DENY EXPLORATION|PROCESSING [IF <condition>]
```

### Default Rules

```shareql
# Default behavior - allow everything
DEFAULT: ALLOW

# Deny exploration of common admin shares
DENY EXPLORATION IF SHARE.NAME IN ['c$','print$','admin$','ipc$']

# Allow exploration of all other shares
ALLOW EXPLORATION
```

### Available Conditions

**Share conditions:**
- `SHARE.NAME` - Share name
- `SHARE.TYPE` - Share type (e.g., "DISKTREE", "IPC", "PRINTQ")

**File/Directory conditions:**
- `FILE.NAME` - File name
- `FILE.EXTENSION` - File extension (e.g., ".txt", ".doc")
- `FILE.SIZE` - File size in bytes
- `DIR.NAME` - Directory name

### Example Rules

```shareql
# Only explore specific shares
DENY EXPLORATION
ALLOW EXPLORATION IF SHARE.NAME IN ['data', 'shared', 'public']

# Skip large files
DENY PROCESSING IF FILE.SIZE > 10000000

# Only process certain file types
DENY PROCESSING
ALLOW PROCESSING IF FILE.EXTENSION IN ['.txt', '.doc', '.pdf', '.xlsx']

# Skip temp directories
DENY EXPLORATION IF DIR.NAME IN ['temp', 'tmp', 'cache']
```

## Cypher Query Examples

After importing the OpenGraph into BloodHound, use these queries to analyze the data:

### Find principals with Full Control access to a share

```cypher
MATCH (p)-[r]->(s:NetworkShareSMB)
WHERE (p)-[:CanDelete]->(s)
  AND (p)-[:CanDsControlAccess]->(s)
  AND (p)-[:CanDsCreateChild]->(s)
  AND (p)-[:CanDsDeleteChild]->(s)
  AND (p)-[:CanDsDeleteTree]->(s)
  AND (p)-[:CanDsListContents]->(s)
  AND (p)-[:CanDsListObject]->(s)
  AND (p)-[:CanDsReadProperty]->(s)
  AND (p)-[:CanDsWriteExtendedProperties]->(s)
  AND (p)-[:CanDsWriteProperty]->(s)
  AND (p)-[:CanReadControl]->(s)
  AND (p)-[:CanWriteDacl]->(s)
  AND (p)-[:CanWriteOwner]->(s)
RETURN p,r,s
```

### Find principals with Write access to a share

```cypher
MATCH x=(p)-[r:CanWriteDacl|CanWriteOwner|CanDsWriteProperty|CanDsWriteExtendedProperties]->(s:NetworkShareSMB)
RETURN x
```

### Find files by name (case insensitive)

```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.name) = toLower("flag.txt")
RETURN p
```

### Find files by extension

```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.extension) = toLower(".vmdk")
RETURN p
```

### Find all shares accessible by a specific user

```cypher
MATCH p=(u:User)-[r]->(s:NetworkShareSMB)
WHERE u.name = "jsmith"
RETURN p
```

### Find files/directories with NTFS write permissions (object-specific)

```cypher
MATCH p=(principal)-[r:CanNTFSWriteData|CanNTFSAppendData|CanNTFSWriteAttributes|CanNTFSWriteEA]->(target)
WHERE target:File OR target:Directory
RETURN p
```

### Find files a principal can effectively read (share + NTFS intersection)

```cypher
MATCH p=(principal)-[:CanEffectiveRead]->(f:File)
RETURN p
```

### Find directories where a principal can effectively write

```cypher
MATCH p=(principal)-[:CanEffectiveWrite]->(d:Directory)
RETURN p
```

### Find principals who can change NTFS permissions or take ownership

```cypher
MATCH p=(principal)-[r:CanNTFSWriteDacl|CanNTFSWriteOwner]->(target)
WHERE target:File OR target:Directory
RETURN p
```

## Project Structure

```
sharehound-go/
├── cmd/sharehound/          # CLI entry point
│   └── main.go
├── pkg/kinds/               # Node and edge type constants
│   └── kinds.go
├── internal/
│   ├── config/              # Configuration management
│   ├── credentials/         # Authentication handling
│   ├── logger/              # Logging system
│   ├── utils/               # Utility functions
│   ├── smb/                 # SMB session and security descriptors
│   ├── sid/                 # SID resolution with caching
│   ├── graph/               # OpenGraph structures
│   ├── collector/           # Share/NTFS rights collectors
│   ├── rules/               # ShareQL parser and evaluator
│   ├── targets/             # Target loading
│   ├── worker/              # Connection pooling and concurrency
│   └── status/              # Progress tracking
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Building

```bash
# Build for current platform
make build

# Build for all platforms (Linux, Windows, macOS - amd64 and arm64)
make build-all

# Run tests
make test

# Format code
make fmt

# Clean build artifacts
make clean
```

## Testing

### Unit Tests

```bash
go test ./...
```

### Integration Tests

Integration tests require a real SMB server. Set environment variables and run:

```bash
export SMB_TEST_HOST="192.168.1.100"
export SMB_TEST_USER="testuser"
export SMB_TEST_PASSWORD="password"
export SMB_TEST_DOMAIN="DOMAIN"        # optional
export SMB_TEST_SHARE="sharename"      # optional

go test -v ./internal/smb -run TestIntegration
```

Available integration tests:
- `TestIntegrationConnect` - Basic SMB connection
- `TestIntegrationListShares` - Share enumeration
- `TestIntegrationListContents` - Directory listing with timestamps
- `TestIntegrationSecurityDescriptor` - NTFS permission retrieval
- `TestIntegrationDirectoryTraversal` - Recursive traversal
- `TestIntegrationShareSecurityDescriptor` - SRVSVC RPC

## Dependencies

- [go-smb2](https://github.com/medianexapp/go-smb2) - SMB2/3 client (fork with NTFS security descriptor support)
- [go-ldap](https://github.com/go-ldap/ldap) - LDAP client for AD integration
- [miekg/dns](https://github.com/miekg/dns) - DNS resolution
- [cobra](https://github.com/spf13/cobra) - CLI framework
- [progressbar](https://github.com/schollz/progressbar) - Progress display

## License

MIT License - see LICENSE file for details.

## Credits

- **Original project:** Remi Gascou ([@podalirius_](https://twitter.com/podalirius_)) @ SpecterOps - [p0dalirius/ShareHound](https://github.com/p0dalirius/ShareHound)
- **Go implementation:** Javier Azofra @ Siemens Healthineers
- **Associated blog post:** [ShareHound: An OpenGraph Collector for Network Shares](https://specterops.io/blog/2025/10/30/sharehound-an-opengraph-collector-for-network-shares/)

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

