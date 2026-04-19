# ShareHound: Mapping rights of network shares using bloodhound OpenGraph

<p align="center">
  A python tool to map the access rights of network shares into a BloodHound OpenGraphs easily
  <br>
  <a href="https://pypi.org/project/sharehound"><img alt="PyPI" src="https://img.shields.io/pypi/v/sharehound"></a>
  <a href="https://github.com/p0dalirius/ShareHound/releases"><img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/p0dalirius/sharehound"></a>
  <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
  <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
  <br>
  <img height=21px src="https://img.shields.io/badge/Get bloodhound:-191646"> <a href="https://specterops.io/bloodhound-enterprise/" title="Get BloodHound Enterprise"><img alt="Get BloodHound Enterprise" height=21px src="https://mintlify.s3.us-west-1.amazonaws.com/specterops/assets/enterprise-edition-pill-tag.svg"></a>
  <a href="https://specterops.io/bloodhound-community-edition/" title="Get BloodHound Community"><img alt="Get BloodHound Community" height=21px src="https://mintlify.s3.us-west-1.amazonaws.com/specterops/assets/community-edition-pill-tag.svg"></a>
  <br>
</p>

Read the associated blogpost: https://specterops.io/blog/2025/10/30/sharehound-an-opengraph-collector-for-network-shares/

## Features

- [x] Map network shares of a domain and their rights in Bloodhound OpenGraph format
- [x] Highly customizable rule matching system based on the [ShareQL language](https://github.com/p0dalirius/shareql)
- [x] Multithreaded discovery of shares in Breadth First Search 

## Quick start cypher queries

To help you get started, here are a set of quick start cypher queries for the most common needs:


<details open><summary><h4>Find principals with Full control access to a share</h4></summary>
The following query will allow you to find principals with full control access to a share

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

This will result in a graph similar to this one (I like to call it the Full Control Onion):

```mermaid
graph LR
    S-1-5-21-3797563538-650367887-713497691-1106[S-1-5-21-3797563538-650367887-713497691-1106] -->| CanDelete | ExampleShare[ExampleShare]
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanDsControlAccess | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanDsCreateChild | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanDsDeleteChild | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanDsDeleteTree | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanDsListContents | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanDsListObject | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanDsReadProperty | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanDsWriteExtendedProperties | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanDsWriteProperty | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanReadControl | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanWriteDacl | ExampleShare
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanWriteOwner | ExampleShare
```
</details>

<details open><summary><h4>Find principals with Write access to a share</h4></summary>
The following query will allow you to find files by name (case insensitive)

```cypher
MATCH x=(p)-[r:CanWriteDacl|CanWriteOwner|CanDsWriteProperty|CanDsWriteExtendedProperties]->(s:NetworkShareSMB)
RETURN x 
```

This will result in a graph similar to this one:

```mermaid
graph LR
    S-1-5-21-3797563538-650367887-713497691-1106[S-1-5-21-3797563538-650367887-713497691-1106] -->| CanWriteDacl | ExampleShare[ExampleShare]
    S-1-5-21-3797563538-650367887-713497691-1106 -->| CanWriteOwner | ExampleShare
    S-1-5-32-544[S-1-5-32-544] -->| CanWriteDacl | SYSVOL[SYSVOL]
    S-1-5-32-544 -->| CanWriteOwner | SYSVOL
    S-1-5-32-544 -->| CanWriteDacl | ExampleShare
    S-1-5-32-544 -->| CanWriteOwner | ExampleShare
```
</details>

<details open><summary><h4>Find files by name (case insensitive)</h4></summary>
The following query will allow you to find files by name (case insensitive)

```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.name) = toLower("flag.txt")
RETURN p
```

This will result in a graph similar to this one:

```mermaid
graph LR
    DC01[DC01] -->| HasNetworkShare | Test[Test]
    Test -->| Contains | Dir1[Dir1]
    Test -->| Contains | DirA[DirA]
    DirA -->| Contains | flag.txtA[flag.txt]
    Dir1 -->| Contains | Dir2[Dir2]
    Dir2 -->| Contains | flag.txt1[flag.txt]
```
</details>

<details open><summary><h4>Find files by extension (case insensitive)</h4></summary>
The following query will allow you to find files by extension (case insensitive)

```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.extension) = toLower(".vmdk")
RETURN p
```

This will result in a graph similar to this one:

```mermaid
graph LR
    DC01[DC01] -->| HasNetworkShare | Test[Test]
    Test -->| Contains | Dir1[Dir1]
    Test -->| Contains | DirA[DirA]
    DirA -->| Contains | SRV02.vmdkA[SRV02.vmdk]
    Dir1 -->| Contains | Dir2[Dir2]
    Dir2 -->| Contains | DC01.vmdk1[DC01.vmdk]
```
</details>

<details open><summary><h4>Find files by extension (case insensitive)</h4></summary>
The following query will allow you to find files by name (case insensitive)

```cypher
MATCH p=(h:NetworkShareHost)-[:HasNetworkShare]->(s:NetworkShareSMB)-[:Contains*0..]->(f:File)
WHERE toLower(f.extension) = toLower(".bat")
RETURN p
```

This will result in a graph similar to this one:

```mermaid
graph LR
    DC01[DC01] -->| HasNetworkShare | Test[Test]
    Test -->| Contains | Dir1[Dir1]
    Test -->| Contains | DirA[DirA]
    DirA -->| Contains | script.batA[script.bat]
    Dir1 -->| Contains | Dir2[Dir2]
    Dir2 -->| Contains | logon.bat1[logon.bat]
```
</details>


### For advanced users

All node types and edges name are defined in the [kinds.py](./sharehound/kinds.py) file, so that you can easily find the name of these to create custom Cypher queries.

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.
