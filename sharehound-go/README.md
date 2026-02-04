# ShareHound Go

A Go implementation of ShareHound - a tool that maps network share access rights into BloodHound OpenGraph format.

## Features

- Enumerate SMB shares and their permissions
- Support for share-level and NTFS-level access rights
- BloodHound OpenGraph JSON output format
- ShareQL rule engine for filtering
- Multithreaded processing with connection pooling
- NTLM and Kerberos authentication support
- Pass-the-hash authentication

## Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Run tests
make test

# Format code
make fmt
```

## Usage

```bash
# Basic usage with password authentication
sharehound --target 192.168.1.100 \
    --auth-domain CORP \
    --auth-dc-ip 192.168.1.1 \
    --auth-user administrator \
    --auth-password 'P@ssw0rd'

# With pass-the-hash
sharehound --target 192.168.1.100 \
    --auth-domain CORP \
    --auth-dc-ip 192.168.1.1 \
    --auth-user administrator \
    --auth-hashes 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'

# With targets file
sharehound --targets-file targets.txt \
    --auth-domain CORP \
    --auth-dc-ip 192.168.1.1 \
    --auth-user administrator \
    --auth-password 'P@ssw0rd' \
    --output results.json

# With custom rules
sharehound --target 192.168.1.0/24 \
    --auth-domain CORP \
    --auth-dc-ip 192.168.1.1 \
    --auth-user administrator \
    --auth-password 'P@ssw0rd' \
    --rules-file custom_rules.txt
```

## Command Line Options

### Output Options
- `-v, --verbose` - Verbose mode
- `--debug` - Debug mode
- `--no-colors` - Disable ANSI escape codes
- `--logfile` - Log file to write to
- `-o, --output` - Output file (default: opengraph.json)

### Advanced Configuration
- `--advertised-name` - Advertised name of the client
- `--threads` - Number of threads to use
- `--max-workers-per-host` - Maximum concurrent shares per host (default: 8)
- `--global-max-workers` - Global maximum workers (default: 200)
- `-n, --nameserver` - Nameserver for DNS queries
- `-t, --timeout` - Timeout in seconds (default: 2.5)
- `--host-timeout` - Maximum time in minutes per host

### Rules
- `-r, --rules-file` - Path to file containing rules
- `--rule-string` - Rule string (can be specified multiple times)

### Share Exploration
- `--share` - Specific share to enumerate
- `--depth` - Maximum depth to traverse (default: 3)
- `--include-common-shares` - Include C$, ADMIN$, IPC$, PRINT$

### Targets and Authentication
- `-f, --targets-file` - Path to file containing targets
- `--target` - Target IP, FQDN or CIDR (can be specified multiple times)
- `--auth-domain` - Windows domain
- `--auth-dc-ip` - Domain controller IP
- `--auth-user` - Username
- `--auth-password` - Password
- `--auth-hashes` - LM:NT hashes
- `--auth-key` - Kerberos key
- `-k, --use-kerberos` - Use Kerberos authentication
- `--kdc-host` - KDC host for Kerberos
- `--ldaps` - Use LDAPS
- `--subnets` - Auto-enumerate domain subnets

## Output Format

The output is a BloodHound OpenGraph JSON file containing:

### Node Types
- `NetworkShareHost` - SMB server
- `NetworkShareSMB` - SMB share
- `File` - File
- `Directory` - Directory

### Edge Types

**Containment:**
- `HostsNetworkShare` - Computer to NetworkShareHost
- `HasNetworkShare` - Host to Share
- `Contains` - Parent to Child

**Share-Level Permissions:**
- `CanGenericRead`, `CanGenericWrite`, `CanGenericExecute`, `CanGenericAll`
- `CanDsCreateChild`, `CanDsDeleteChild`, `CanDsListContents`, etc.
- `CanDelete`, `CanReadControl`, `CanWriteDacl`, `CanWriteOwner`

**NTFS-Level Permissions:**
- `CanNTFSGenericRead`, `CanNTFSGenericWrite`, `CanNTFSGenericExecute`, `CanNTFSGenericAll`
- `CanNTFSDelete`, `CanNTFSReadControl`, `CanNTFSWriteDacl`, etc.

## ShareQL Rules

Rules use the ShareQL language to filter what gets explored and processed:

```
# Default behavior
DEFAULT: ALLOW

# Deny exploration of common admin shares
DENY EXPLORATION IF SHARE.NAME IN ['c$','print$','admin$','ipc$']

# Allow exploration of all other shares
ALLOW EXPLORATION

# Deny processing large files
DENY PROCESSING IF FILE.SIZE > 10000000

# Only process certain file types
ALLOW PROCESSING IF FILE.EXTENSION IN ['.txt', '.doc', '.pdf']
```

## License

MIT License - see LICENSE file for details.
