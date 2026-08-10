# Upgrade program decision record

Date: 2026-08-10

Decision owner: project owner

Technical owner: `@kiranmagic7`

Status: implementation authorized, launch closed

## Decision

Implement the BehaviorLock engineering and usability program as a sequence of reversible, issue-backed changes. The program may use public development branches and hosted CI to prove Linux container behavior. It must not create a release tag, publish a Marketplace action, promote the project, execute live malware, or merge to protected `main` without a separate owner decision.

## Mission served

Make bounded npm behavior changes inspectable without presenting BehaviorLock as a malware verdict, safety proof, or complete sandbox.

## Product contract

1. BehaviorLock reports observations and review levels. It does not classify package intent.
2. Every trusted report item must point to retained, content-addressed raw evidence.
3. Acquisition and package execution remain separate trust boundaries.
4. Package execution remains offline by default.
5. Trusted automation captures both versions itself and never accepts pull-request-supplied profiles as authority.
6. Ambiguous, incomplete, incompatible, or unverifiable evidence fails closed.

## Authorized work

1. Implement the fourteen release-gate proof paths with inert fixtures and hosted Linux evidence.
2. Replace verdict-oriented output with threshold and review language before the first tagged schema contract.
3. Retain raw evidence separately from normalized profiles and add verifiable evidence references.
4. Restrict acquisition to an internal Docker network and an exact-host allowlist proxy.
5. Add artifact provenance verification, SBOM generation, signed release configuration, and release dry runs without creating a tag.
6. Expand selected syscall coverage, descriptor attribution, process relationships, environment-probe evidence, canaries, and observable technique sequences.
7. Build split-privilege CI integration without `pull_request_target` and without Marketplace publication.
8. Add deterministic fixtures, repeated-run checks, safe benchmark metadata, runbooks, and an incident-response template.

## Modified or rejected work

1. `pull_request_target` is rejected. A privileged workflow must never execute code or package selections controlled by a pull request.
2. Global noise suppression from a no-op package is rejected. Repeated observations may report frequency, but credential, network, process, environment-probe, and out-of-boundary mutation evidence is never suppressible.
3. Sandbox camouflage that weakens a read-only root, process identity, procfs integrity, or container isolation is rejected. BehaviorLock reports environment probes instead of claiming invisibility.
4. Clock injection and automatic sleep skipping are rejected for the trusted default because they change program semantics. Timing probes may be observed while the hard wall-clock limit remains authoritative.
5. Privileged eBPF and unverified gVisor syscall claims are deferred. Capture-backend identity and compatibility checks may be added without claiming unsupported evidence.
6. Live malware execution on GitHub-hosted runners is rejected pending explicit platform-policy, legal, and isolation approval. The benchmark harness uses inert reconstructions and metadata only.
7. No release-candidate or stable tag is created while any release gate is open.

## Workstream order

1. Reconcile existing documentation and containment work.
2. Stabilize terminology and evidence contracts.
3. Close containment, exhaustion, tracer-death, and determinism implementation gaps.
4. Close acquisition-egress and provenance implementation gaps.
5. Add bounded observation coverage.
6. Add safe CI integration and no-publish release machinery.
7. Complete security and truth audits before any merge or release decision.

## Risk and reversibility

Every implementation change uses a dedicated branch or local integration branch. The pre-program repository refs and uncommitted containment work are preserved in a verified Git bundle and patch under the workspace backup directory. Public merges, releases, promotion, and live-sample research remain separate owner decisions.

## Success measures

1. Every roadmap gate has an explicit proof path and reports fail-closed state for the exact protected commit.
2. `make check`, builds, security scanners, schema tests, and release dry runs pass on the implementation stack.
3. Acquisition package tooling has no direct route and can reach only the exact registry proxy through a private Unix socket.
4. Every current diff addition has a raw-evidence reference whose content digest verifies.
5. Cross-workflow consumers verify artifact provenance before privileged use.
6. Documentation states tested coverage and limitations without unsupported detection claims.
7. A new user can build, run the inert demonstration, operate capture on a disposable Linux runner, and understand the output.

## Approval state

Implementation and hosted CI branches are approved. Merge to `main`, release tags, package or image publication, Marketplace publication, external outreach, and live malware execution are not approved by this record.

## Next review

Review after all automated checks are green on the final draft stack and before any merge or release decision.
