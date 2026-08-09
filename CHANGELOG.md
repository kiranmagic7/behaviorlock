# Changelog

All notable changes will be documented here. The project follows Keep a Changelog and Semantic Versioning.

## Unreleased

### Added

1. Strict exact npm package specification parser
2. Bounded `strace` parser and normalized behavior profiles
3. Deterministic profile comparison with transparent review rules
4. Experimental two phase Docker capture backend
5. JSON, text, and Markdown output
6. Profile and diff schemas
7. Threat model, limitations, governance, contribution, and security documentation
8. Dependency lock and runner provenance
9. Root owned trace channel separated from the package uid
10. Semantic JSON Schema conformance tests
11. Explicit `attestation: none` provenance boundary for unsigned profiles
12. Separate user guide, platform support guide, technical reference, and security audit record
13. Raw evidence companions with whole-artifact and exact-line verification
14. Exact-registry acquisition proxy reached from network-none preparation through a private Unix socket
15. Explicit runner selection with immutable image resolution and runner-reference comparability
16. No-publish release dry run with archive and runner SBOMs
17. Fail-closed 14-gate release proof validator and protected trusted-profile attestation workflow

### Changed

1. New reads of exact container, tracing, and environment fingerprint paths now receive medium review rule `BL600`.
2. General file reads and metadata inspections keep low review rule `BL500`; sensitive-path rule `BL100` retains precedence.
3. Numeric `/proc/<pid>` paths now normalize to the literal `/proc/$PID` token instead of collapsing the pid segment.

### Security

1. Capture requires explicit experimental acknowledgement.
2. Empty, incomplete, timed out, truncated, malformed, or sentinel missing traces are rejected.
3. Package input cannot control Docker flags, images, mounts, environment names, or container names.
4. External traces require explicit acknowledgement before comparison.
5. Runner and prepared package images execute by immutable Docker content ID after resolution.
6. Any `strace` diagnostic fails capture before a trusted completion footer is emitted.
7. Runtime profile validation now enforces npm integrity, content ID, coverage, and behavior limits.
8. Path normalization applies only at genuine disposable root boundaries.
9. Docker client proxy variables are explicitly cleared in every runner container.
10. Protected main DCO verification recognizes GitHub created squash identities without relaxing strict pull request checks.
11. CodeQL uses the fully pinned v4 action line before the v3 retirement deadline.
12. Release and attestation workflows are manual, SHA-pinned, least-privilege, protected-environment gated, and disabled by repository variables by default.
