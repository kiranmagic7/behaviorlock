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

### Security

1. Capture requires explicit experimental acknowledgement.
2. Empty, incomplete, timed out, truncated, malformed, or sentinel missing traces are rejected.
3. Package input cannot control Docker flags, images, mounts, environment names, or container names.
4. External traces require explicit acknowledgement before comparison.
