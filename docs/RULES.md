# Review rule registry

BehaviorLock rule identifiers describe new observations. They do not classify a package or infer intent. The machine-readable registry is `config/rules-v1.json`; documentation and code must preserve an existing identifier's meaning once it has been assigned.

## Current rules

| Rule | Level | Observation family |
| --- | --- | --- |
| `BL100` | Critical | Common credential or secret path access |
| `BL200` | High | Network connection attempt |
| `BL201` | High | Network send attempt |
| `BL202` | High | Network send to port 53; payload not decoded |
| `BL203` | High | Bind or listen setup |
| `BL204` | Medium | Inbound connection acceptance attempt |
| `BL205` | Low | Socket creation |
| `BL300` | High | Shell, downloader, or remote-access process |
| `BL301` | Medium | Executable process |
| `BL302` | Medium | Child process creation without requiring an exec |
| `BL303` | High | Anonymous memory file or descriptor-backed execution |
| `BL304` | Medium | Process tracing or inspection attempt |
| `BL400` | High | Mutation outside disposable writable roots |
| `BL401` | Medium | Mutation inside a disposable writable root |
| `BL402` | Medium | Deletion or permission change |
| `BL403` | High | Truncation or descriptor-backed file mutation |
| `BL500` | Low | Ordinary file read or metadata inspection |
| `BL501` | Low | Directory enumeration |
| `BL600` | Medium | Container, tracing, or environment fingerprint path access |
| `BL601` | Low | Clock inspection or requested delay |
| `BL900` | Low | Observation without a more specific current rule |

Sensitive-path precedence is absolute: a behavior that also matches another family remains `BL100`. `BL500` continues to mean ordinary reads. `BL600` is reserved for exact, bounded environment-fingerprint paths and is not a generic anti-analysis bucket.

DNS is identified from an observed network send whose endpoint uses port 53. BehaviorLock does not decode or retain arbitrary DNS payloads, so `BL202` establishes an attempted DNS transport, not a verified domain name or successful lookup.

Descriptor attribution is explicit. If the parser can follow an open, socket, duplicate, fork, close, or descriptor reuse, it reports the known normalized path or endpoint. Otherwise it reports `fd:unknown`. It never guesses a filename from unrelated trace text.

Process IDs, parent IDs, and descriptor numbers can appear in bounded `runtime` attribution objects. They are evidence coordinates, not semantic keys. Stable behavior IDs and profile digests exclude them.

Some rules include optional MITRE ATT&CK references. Every reference uses the literal relationship `consistent with`. This metadata is review navigation only: it does not assert that a technique occurred, change a rule's review level, affect thresholds, or classify a package.
