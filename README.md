# ShareHound: Mapping rights of network shares using BloodHound OpenGraph

<p align="center">
  A tool to map the access rights of network shares into BloodHound OpenGraphs.
  <br>
  <img height=21px src="https://img.shields.io/badge/Get bloodhound:-191646"> <a href="https://specterops.io/bloodhound-enterprise/" title="Get BloodHound Enterprise"><img alt="Get BloodHound Enterprise" height=21px src="https://mintlify.s3.us-west-1.amazonaws.com/specterops/assets/enterprise-edition-pill-tag.svg"></a>
  <a href="https://specterops.io/bloodhound-community-edition/" title="Get BloodHound Community"><img alt="Get BloodHound Community" height=21px src="https://mintlify.s3.us-west-1.amazonaws.com/specterops/assets/community-edition-pill-tag.svg"></a>
  <br>
</p>

Read the associated blog post: https://specterops.io/blog/2025/10/30/sharehound-an-opengraph-collector-for-network-shares/

## Two implementations

This repository contains two implementations of ShareHound. They share the same
goal — producing BloodHound OpenGraph JSON from SMB share permissions — but
differ in language, runtime, and feature set. Pick whichever fits your workflow.

| Implementation | Path | Author | Best for |
|---|---|---|---|
| **Python** | [`Python/`](./Python) | Remi Gascou ([@podalirius_](https://twitter.com/podalirius_)) @ SpecterOps | The reference implementation; easy to extend and script |
| **Go** | [`Go/`](./Go) | Javier Azofra @ Siemens Healthineers | Large-scale scans (60,000+ hosts), checkpointing, static binaries |

Each subdirectory has its own README with full installation, usage, and
configuration details:

- [`Python/README.md`](./Python/README.md)
- [`Go/README.md`](./Go/README.md)

## Features (common to both)

- Map network shares of a domain and their rights in BloodHound OpenGraph format
- Highly customizable rule matching via the [ShareQL language](https://github.com/p0dalirius/shareql)
- Multithreaded discovery of shares (Breadth First Search)
- NTLM, Kerberos, and pass-the-hash authentication
- CIDR range and target file support

### Additional features in the Go implementation

- ZIP-compressed streaming output (handles millions of edges)
- Resumable scans via checkpoint files
- `--effective-access-only` mode to drastically reduce graph size on large environments
- Cross-platform static builds (Linux, Windows, macOS)

## Quick start Cypher queries

Once you've imported the OpenGraph into BloodHound, these queries cover the
most common needs. For more, see the per-implementation READMEs.

<details open><summary><h4>Find principals with Full Control access to a share</h4></summary>

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
</details>

<details open><summary><h4>Find principals with Write access to a share</h4></summary>

```cypher
MATCH x=(p)-[r:CanWriteDacl|CanWriteOwner|CanDsWriteProperty|CanDsWriteExtendedProperties]->(s:NetworkShareSMB)
RETURN x
```
</details>

<details open><summary><h4>Find files by name (case insensitive)</h4></summary>

```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.name) = toLower("flag.txt")
RETURN p
```
</details>

<details open><summary><h4>Find files by extension (case insensitive)</h4></summary>

```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.extension) = toLower(".vmdk")
RETURN p
```
</details>

<details open><summary><h4>Find files a principal can effectively read (Go only)</h4></summary>

`CanEffectiveRead` / `CanEffectiveWrite` / `CanEffectiveExecute` edges are emitted
by the Go implementation when the same SID has matching rights at both the share
and NTFS levels — i.e. the real access granted over SMB.

```cypher
MATCH p=(principal)-[:CanEffectiveRead]->(f:File)
RETURN p
```
</details>

## Credits

- **Original project:** Remi Gascou ([@podalirius_](https://twitter.com/podalirius_)) @ SpecterOps — [p0dalirius/ShareHound](https://github.com/p0dalirius/ShareHound)
- **Go implementation:** Javier Azofra @ Siemens Healthineers
- **Associated blog post:** [ShareHound: An OpenGraph Collector for Network Shares](https://specterops.io/blog/2025/10/30/sharehound-an-opengraph-collector-for-network-shares/)

## Contributing

Pull requests are welcome for either implementation. Open an issue if you want
to discuss a new feature first.
