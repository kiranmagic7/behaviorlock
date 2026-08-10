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
18. Versioned review-rule registry with stable identifiers for expanded observations
19. UDP/DNS, listener, descriptor mutation, directory enumeration, process lineage, anonymous-memory execution, ptrace, and timing observation
20. Bounded per-process descriptor and lineage context with explicit unknown attribution
21. Distinct timeout, cancellation, signal, truncation, and authoritative Docker OOM result mapping
22. Inert resource-boundary and real-tracer-death fixtures with cleanup assertions
23. Ten-run semantic repeatability check that reports raw and count variance without suppression
24. Distinct generated nonsecret canaries for disposable credential-file and environment locations
25. Bounded first-seen observation sequences grouped by process lineage
26. Explicit CommonJS or ESM entry-point import observation with unsupported outcomes
27. Optional no-route loopback sinkhole with fixed DNS, HTTP, and TCP responses
28. Schema v3 contracts for phase, canary, sequence, import, sinkhole, and optional ATT&CK context metadata
29. Split-privilege dependency-review automation with API-only head manifest extraction, independently validated data artifacts, and sanitized sticky comments
30. Strict inert regression corpus with exact behavior and rule expectations plus projection-only historical mapping
31. Deterministic JSON and Markdown benchmark reports with citation, phase, reconstruction, and unsupported-signal metadata
32. Operator runbooks for capture, evidence, acquisition, tracing, resources, verification, rollback, and cleanup
33. Coordinated incident-analysis template with authorization, disclosure, redaction, uncertainty, and publication approval gates
34. Offline 30-second demo, reproducible terminal-recording source, and a clean-checkout usability journey
35. Enumerated 14-gate status reporter that preserves all blocked reasons and never grants release authority
36. Local usability observation schema for setup, capture, evidence, replay, comprehension, false-positive feedback, and cleanup

### Changed

1. New reads of exact container, tracing, and environment fingerprint paths now receive medium review rule `BL600`.
2. General file reads and metadata inspections keep low review rule `BL500`; sensitive-path rule `BL100` retains precedence.
3. Numeric `/proc/<pid>` paths now normalize to the literal `/proc/$PID` token instead of collapsing the pid segment.
4. Profile compatibility now requires the same explicit observation-policy version.
5. Capture retains per-process trace identity for review without making runtime identifiers part of semantic behavior identity or the stable digest.
6. Execution now applies a 64 MiB per-file limit in addition to existing process, memory, descriptor, tmpfs, output, syscall, and wall-clock bounds.
7. Current profile and diff kinds are phase-neutral: `npm.observation.profile` and `npm.observation.diff`.
8. Comparison now rejects cross-phase profiles and requires human review for an added observed sequence without inventing a review level.
9. Network rule descriptions now refer to the selected observation phase rather than assuming lifecycle-only execution.

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
13. Generated canary values are never copied from the host or stored in normalized profile metadata.
14. The optional sinkhole has no routed network, retains only bounded request counts and matching canary identifiers, and discards request bytes.
15. Dependency review rejects `pull_request_target`, pull-request head checkout, contributor-supplied profiles, artifact Markdown, unpinned actions, and any execution in the comment-privileged workflow.
