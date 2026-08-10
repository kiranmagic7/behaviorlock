# Security audit

## Review record

| Field | Value |
| --- | --- |
| Review date | 2026-08-08 |
| Reviewed base | `2594d5c32961cb1b55508effbe1bf5e9225e9557` |
| Scope | Go CLI, Docker orchestration, runner scripts, parser, model validation, report rendering, schemas, and GitHub Actions |
| Release status | Experimental, no tag |
| Overall decision | Suitable for continued public experimentation after the fixes in this change. Not approved as a malware sandbox or stable security product. |

The schema v2 retained-evidence work was implemented after this reviewed base. Its local regression suite checks whole-artifact and exact-line tamper rejection, but it does not inherit this audit decision. A new review and hosted evidence are required before release gate 13 can be closed.

## Method

The review combined:

1. Manual data flow and trust boundary review
2. Docker argument and lifecycle analysis
3. Adversarial reasoning about package controlled input
4. `gosec` across all Go packages
5. `govulncheck` at symbol level
6. `go vet`, race enabled tests, and Staticcheck
7. Bounded fuzzing of package specification and trace parsers
8. ShellCheck and shell syntax checks
9. Actionlint and manual GitHub Actions permission review
10. GitHub Dependabot, code scanning, and secret scanning alert review

No live malicious package was executed. Adversarial behavior uses inert local fixtures only.

## Fixed findings

### High: Docker client proxy configuration could enter containers

Docker can automatically populate proxy environment variables from the operator's client configuration. Proxy values may contain internal addresses or credentials. The previous Docker argument allowlist did not explicitly override them, so package code could potentially read values that the tool claimed were not inherited.

The fix explicitly sets uppercase and lowercase HTTP, HTTPS, all proxy, and no proxy variables to empty in preparation, execution, and metadata containers. Unit tests inspect every Docker argument vector, and the hosted package fixture fails if any proxy value is visible.

### Medium: mutable runner reference after evidence collection

The capture path inspected the local runner tag and recorded its image ID, but later commands still used the tag. Another local process with Docker authority could retag it between inspection and execution. A profile could then name one runner ID while execution used another image.

The fix resolves the tag once, validates the returned SHA 256 content ID, and uses that immutable ID for version inspection and preparation. The committed package filesystem is also executed by its returned content ID. Regression tests reject mutable references and invalid commit output.

### Medium: tracer diagnostics could look like a package failure

The runner relied on the `strace` exit code, which normally mirrors the traced command. A tracer failure can also return a nonzero code. Without checking the root owned diagnostic channel, some tracer failures could be reported as an ordinary lifecycle command failure instead of incomplete evidence.

The fix requires the `strace` diagnostic file to remain empty. Any diagnostic now fails capture before a trusted footer is emitted. Hosted integration builds a fake tracer that emits valid looking sentinel lines plus a diagnostic and verifies fail closed behavior.

### Low: path normalization rewrote lookalike roots

Normalization replaced `/work` and `/home/scanner` wherever those strings appeared. Paths such as `/workspace/file` could be rewritten even though they were outside the disposable root.

The fix replaces roots only when the path is exactly the root or begins with the root followed by `/`. Regression tests cover both genuine and lookalike roots.

### Low: runtime profile validation was weaker than the JSON schema

The Go validator accepted any string beginning with `sha512-` as registry integrity and did not fully bound coverage arrays or behavior counts. It also did not require a captured runner image ID to be a SHA 256 digest.

The fix validates the decoded SHA 512 length, runner image content ID, lifecycle and completeness values, coverage text, item counts, and normalized profile state. The JSON schema now carries the same count and coverage limits.

## Open design risks

### Acquisition has broad outbound network access

Preparation needs npm registry access. Lifecycle scripts are disabled, but package and transitive dependency metadata can still influence what npm fetches. The preparation container can potentially reach destinations beyond the public npm registry, including addresses reachable from the Docker bridge.

This remains a release blocker. Until an allowlisted acquisition proxy, equivalent egress control, or a stronger disposable virtual machine design exists, capture must run on an ephemeral host with no access to private networks, cloud metadata, trusted services, or credentials.

### Containers share the host kernel

The package process has no host mounts, no Docker socket, no network during lifecycle execution, and zero effective capabilities. It still shares a kernel with the Docker host or Docker Desktop virtual machine. A kernel or container runtime exploit is outside the protection offered by this harness.

### Profiles are unsigned

Anyone can edit JSON provenance fields. Structural validation cannot establish authenticity. Enforcement workflows must create both profiles in a protected trusted job and must not accept contributor supplied profiles as policy evidence.

### Observation is incomplete

The parser covers selected system calls and one install lifecycle path. It does not capture file contents, ordinary in process environment reads, all network operations, every filesystem mutation, delayed behavior, or normal package runtime.

## Tool results

| Check | Result during this review |
| --- | --- |
| `gosec` | 0 findings across 7 Go source packages |
| `govulncheck` | 0 reachable vulnerabilities |
| Staticcheck | 0 findings |
| GitHub Dependabot alerts | 0 open alerts |
| GitHub code scanning alerts | 0 open alerts |
| GitHub secret scanning alerts | 0 open alerts |
| Package specification fuzzing | No failure during the bounded local run |
| Trace parser fuzzing | No failure during the bounded local run |
| Existing hosted CodeQL | Green on reviewed base |
| Existing hosted Docker integration | Green on reviewed base |

The local Go toolchain reported vulnerabilities in standard library or imported code paths that BehaviorLock does not call. `govulncheck` found zero symbol reachable vulnerabilities in BehaviorLock. Future distributed binaries must be built with a fully patched Go toolchain.

## Release decision

This review does not open the `v0.1.0` release gate. The project may continue as an explicitly experimental source repository. A tagged release still requires every adversarial item in [ROADMAP.md](../ROADMAP.md), stronger acquisition isolation, and verifiable profile provenance.

## Reporting a new issue

Do not publish a vulnerability in a public issue. Use [GitHub private vulnerability reporting](https://github.com/kiranmagic7/behaviorlock/security/advisories/new) and follow [SECURITY.md](../SECURITY.md).
