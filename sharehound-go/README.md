# ShareHound Go

A Go implementation of [ShareHound](https://github.com/p0dalirius/ShareHound) - a tool that maps network share access rights into BloodHound OpenGraph format for security analysis.

**Original Python version by Remi Gascou ([@podalirius_](https://twitter.com/podalirius_)) @ SpecterOps**
**Go port by Javier Azofra @ Siemens Healthineers**

This is a complete port with **full feature parity** with the Python version, producing identical graph structures compatible with BloodHound Enterprise and Community editions.

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
git clone https://github.com/specterops/sharehound.git
cd sharehound/sharehound-go

# Build for current platform
make build

# Or build for all platforms
make build-all
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
| `File` | A file on a share |
| `Directory` | A directory on a share |
| `Principal` | A security principal (generic) |
| `User` | A user principal |
| `Group` | A group principal |

### Edge Types (28 total)

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

#### NTFS-Level Permission Edges (11)
- `CanNTFSGenericRead` - NTFS generic read
- `CanNTFSGenericWrite` - NTFS generic write
- `CanNTFSGenericExecute` - NTFS generic execute
- `CanNTFSGenericAll` - NTFS full control
- `CanNTFSMaximumAllowed` - Maximum allowed access
- `CanNTFSAccessSystemSecurity` - Access system security
- `CanNTFSSynchronize` - Synchronize access
- `CanNTFSWriteOwner` - NTFS take ownership
- `CanNTFSWriteDacl` - NTFS modify DACL
- `CanNTFSReadControl` - NTFS read security descriptor
- `CanNTFSDelete` - NTFS delete permission

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

## Feature Parity with Python Version

This Go implementation maintains full feature parity with the original Python ShareHound:

- Same 9 node types
- Same 28 edge types
- Same access mask mappings (17 share-level, 11 NTFS-level)
- Same ShareQL rule syntax
- Same output format (BloodHound OpenGraph JSON)
- Same CLI flags and behavior

## License

MIT License - see LICENSE file for details.

## Credits

- **Original Python implementation:** Remi Gascou ([@podalirius_](https://twitter.com/podalirius_)) @ SpecterOps - [p0dalirius/ShareHound](https://github.com/p0dalirius/ShareHound)
- **Go port:** Javier Azofra @ Siemens Healthineers
- **Associated blog post:** [ShareHound: An OpenGraph Collector for Network Shares](https://specterops.io/blog/2025/10/30/sharehound-an-opengraph-collector-for-network-shares/)

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
