# BehaviorLock

BehaviorLock shows how behavior observed during one bounded npm package phase changes between two exact versions. Offline install lifecycle observation is the default; entry-point import observation is an explicit experiment.

Source review and vulnerability databases answer important questions about a dependency update. BehaviorLock asks another one: did the new version begin reading a credential path, starting a shell, changing files, or attempting a network connection during the selected bounded phase?

It records selected Linux system calls from both versions, normalizes the results, and produces a diff that a person can inspect or a CI job can evaluate.

> [!WARNING]
> BehaviorLock is an experimental observation tool. It is not a malware sandbox and does not prove that a package is safe. Unknown packages belong in a dedicated disposable virtual machine with no credentials or private-network access, never on a personal workstation or privileged CI runner.

## A simple example

Imagine that version 1.0.0 creates a cache directory during installation. Version 1.1.0 does the same thing, but also starts a shell and tries to read an SSH key path.

BehaviorLock reports the shell launch and credential path read as new observations. It does not decide why they happened. A maintainer reviews the evidence and decides whether the change is expected.

## Status at a glance

| Question | Current answer |
| --- | --- |
| Maturity | Public experiment, `0.1.0-dev` |
| Package ecosystem | Public npm registry packages |
| Version input | Exact semantic versions only |
| Observed environment | Linux container install lifecycle; optional experimental package import |
| CLI build and unit tests | Linux and macOS |
| Full Docker integration | GitHub hosted Linux runner |
| Native Windows or macOS tracing | Not supported |
| Evidence integrity | Raw trace retained separately and verified by digest and line references |
| Acquisition egress | Preparation has `--network none`; an exact-host proxy is reached through a private Unix socket |
| Profile authenticity | Ordinary profiles are unsigned; a protected, disabled-by-default attestation workflow exists for reviewed fixtures |
| Dependency review automation | Split-privilege workflows implemented; inactive until reviewed and merged to the protected default branch |
| Tagged release | None |

## What it observes

The current parser records a bounded subset of:

1. Path- and descriptor-based file reads, writes, creation, truncation, deletion, renaming, permission changes, and directory enumeration
2. Executable launches, child creation, anonymous memory files, descriptor-backed execution, and process inspection
3. Socket creation, connection, UDP/DNS send, bind, listen, and acceptance attempts
4. Selected clock inspection and requested delay calls
5. Whether an observed call succeeded, failed, or was blocked, with bounded process, parent, descriptor, and attribution context
6. Exact movement of generated nonsecret canaries when visible in an already observed process argument, filesystem target, or bounded sinkhole request
7. Selected observed-order sequences grouped without retaining runtime PIDs in their stable identity

The default capture path exercises npm `preinstall`, `install`, and `postinstall` scripts through `npm rebuild`. `--phase import` instead loads the resolved CommonJS or ESM package entry point and produces a separate, non-comparable coverage scope. Neither mode observes total application runtime behavior.

## How it works

```text
exact npm version
       |
       v
prepare without lifecycle scripts
       |
       v
resolve immutable package filesystem
       |
       v
run the selected phase offline under strace
       |
       v
retain evidence, validate, and normalize a profile
       |
       v
compare two compatible profiles
       |
       v
JSON, text, or Markdown report
```

Preparation and execution are separate. Preparation runs with lifecycle scripts disabled and Docker network mode `none`. Its only acquisition path is a loopback relay into a private Docker-volume Unix socket. The proxy sidecar accepts CONNECT only for `registry.npmjs.org:443`, rejects unsafe DNS answers, and dials the validated public address itself. Execution starts from the prepared filesystem, uses a read only root filesystem, receives no host mounts or inherited credentials, and runs package code as uid `65532` with zero effective capabilities. Execution is offline by default. The optional sinkhole shares only an unrouted loopback namespace and returns fixed inert responses.

The proxy does not make package acquisition trustworthy. Registry metadata and package archives remain untrusted, and the proxy shares the Docker host kernel. Use capture only on a disposable runner with no valuable credentials or workloads.

## Try the comparison without Docker

Go 1.23 or newer is required.

For the shortest safe product journey, run the offline demo. It replays hand-written inert traces, verifies both raw-evidence companions, renders the difference, and cleans up without downloading or executing a package:

```bash
./scripts/demo-inert.sh
```

```bash
go build -trimpath -o bin/behaviorlock ./cmd/behaviorlock

bin/behaviorlock profile \
  --package example@1.0.0 \
  --trace testdata/traces/baseline.strace \
  --output baseline.profile.json

bin/behaviorlock profile \
  --package example@1.1.0 \
  --trace testdata/traces/candidate.strace \
  --output candidate.profile.json

bin/behaviorlock compare \
  --allow-external \
  --baseline baseline.profile.json \
  --candidate candidate.profile.json \
  --format markdown \
  --output behaviorlock.report.md
```

These traces are inert fixtures. Profiles created with `profile --trace` are marked `external-unverified`. Comparison rejects them unless `--allow-external` is present because their capture conditions and provenance cannot be verified.

Each profile command also creates a mode `0600` companion such as `baseline.profile.json.evidence.strace`. The profile records the artifact digest and bounded line references. `validate` and `compare` verify the whole artifact and every referenced line before accepting the profile. The raw trace can contain sensitive paths and process arguments; keep the companion private and review it before sharing.

## Capture a public npm package

Docker is required. Build the pinned runner image from this repository first.

```bash
make runner
make build
bin/behaviorlock doctor --runner behaviorlock-runner:dev

bin/behaviorlock capture \
  --experimental \
  --runner behaviorlock-runner:dev \
  --package is-number@7.0.0 \
  --phase lifecycle \
  --timeout 2m \
  --output is-number.profile.json
```

`--experimental` is mandatory. `--runner` must name an explicit non-`latest` tag, local content ID, or `@sha256` digest reference. The command records that reference, its resolved image ID, architecture, Node version, npm version, `strace` version, package registry integrity, dependency lock digest, acquisition policy version, allowed authority, phase, and proxy image ID. It also retains `is-number.profile.json.evidence.strace` unless `--evidence-output` selects another path. Docker execution uses the immutable image ID after resolution so a mutable local tag cannot silently change the captured environment.

To observe first import separately, select `--phase import`. Add `--sinkhole` only when a fixed inert loopback responder is useful. Both are experimental; neither changes the offline lifecycle default. See [canary, import, and sinkhole observations](docs/CANARY_IMPORT_AND_SINKHOLE.md).

Do not capture an unknown package on a machine that contains valuable data, credentials, trusted workloads, or access to private infrastructure.

## Compare two captured versions

Both profiles must describe the same package and use the same phase, runner image reference and ID, architecture, Node version, npm version, `strace` version, network mode, sinkhole policy when present, sandbox profile, coverage scope, and observation policy. Lifecycle and import profiles are rejected as incomparable. Their companion evidence files must be present beside the profiles, or supplied with `--baseline-evidence` and `--candidate-evidence`.

```bash
bin/behaviorlock compare \
  --baseline package-1.0.0.profile.json \
  --candidate package-1.1.0.profile.json \
  --fail-on high \
  --format markdown \
  --output behaviorlock.report.md
```

The default threshold is `high`. Exit code `1` means an added observation reached the selected threshold. It does not mean the package is malicious.

## Reading a report

| Rule | Level | Meaning |
| --- | --- | --- |
| `BL100` | Critical | New access to a common credential or secret path |
| `BL200` | High | New network connection attempt during the selected phase |
| `BL201` | High | New network send attempt during the selected phase |
| `BL202` | High | New network send to port 53 during the selected phase; payload not decoded |
| `BL203` | High | New bind or listener setup |
| `BL204` | Medium | New inbound acceptance attempt |
| `BL205` | Low | New socket creation |
| `BL300` | High | New shell, downloader, or remote access process |
| `BL301` | Medium | New executable process |
| `BL302` | Medium | New child process creation |
| `BL303` | High | New anonymous memory file or descriptor-backed execution |
| `BL304` | Medium | New process tracing or inspection attempt |
| `BL400` | High | New mutation outside disposable work and temporary roots |
| `BL401` | Medium | New mutation inside a disposable writable root |
| `BL402` | Medium | New deletion or permission change |
| `BL403` | High | New truncation or descriptor-backed mutation |
| `BL500` | Low | New file read or metadata inspection |
| `BL501` | Low | New directory enumeration |
| `BL600` | Medium | New access to a path commonly used to detect containers or tracing |
| `BL601` | Low | New clock inspection or requested delay |

`BL600` covers exact normalized paths such as `/.dockerenv`, `/run/.containerenv`, selected `/proc` environment fingerprints, and `/sys/class/dmi` or its descendants. Boundary matching prevents lookalike paths from receiving this rule. These reads can be legitimate diagnostics; the rule reports evidence for review and does not establish evasive or malicious intent. Ptrace and timing observations have their own identifiers instead of changing the established meaning of `BL500` or `BL600`.

The complete versioned registry and attribution rules are in [review rules](docs/RULES.md).

The report exposes `reviewRequired` and `highestReviewLevel`; it does not issue a package verdict. An added observed sequence also requires review, but a sequence-only change keeps `highestReviewLevel: none` because ordering context receives no invented level. The CLI threshold controls only the process exit code. No observed addition, or an exit code of `0`, authenticates the profiles, establishes full coverage, or proves safety.

## Command reference

```text
behaviorlock doctor [--runner image:tag-or-digest]
behaviorlock capture --experimental --runner image:tag-or-digest --package name@1.2.3 --output profile.json [--phase lifecycle|import] [--sinkhole] [--evidence-output raw.strace]
behaviorlock profile --package name@1.2.3 --trace raw.strace --output profile.json [--evidence-output retained.strace]
behaviorlock compare --baseline old.json --candidate new.json --output report.json [--baseline-evidence old.strace --candidate-evidence new.strace]
behaviorlock validate --profile profile.json [--evidence raw.strace]
behaviorlock version
```

Exit codes:

1. `0` means the command completed and the comparison threshold was not reached.
2. `1` means a comparison reached the selected review threshold.
3. `2` means invalid input, incomplete evidence, sandbox failure, or another runtime error.

## Platform support

The Go parser and comparison code build and run on Linux and macOS. The capture backend observes Linux behavior because it depends on Linux containers, Linux permissions, and `strace`.

Docker Desktop may allow a macOS or Windows host to operate a Linux container, but that still produces a Linux profile. Native Windows and native macOS behavior are outside this version, and Windows is not yet part of the CI build matrix.

See [platform support](docs/PLATFORM_SUPPORT.md) for the exact distinction between host compatibility and observed target behavior.

## Security boundary

The capture backend uses defense in depth:

1. Strict package input validation before Docker runs
2. Docker argument arrays instead of host shell interpolation
3. No host mounts, Docker socket, inherited home directory, inherited credentials, or Docker client proxy variables
4. Offline selected-phase execution by default and a read only root filesystem
5. Bounded memory, CPU, processes, descriptors, temporary storage, output, and wall clock time
6. A root owned trace directory that package code cannot read or modify
7. Immutable Docker content IDs for the runner and prepared package filesystem
8. Required trace sentinels, completion evidence, and an empty tracer diagnostic channel
9. Separate mode `0600` evidence artifacts whose full digest and referenced line digests are verified before comparison
10. Preparation network mode `none`, with registry traffic crossing only a private Unix socket into an exact-authority proxy

Containers still share a kernel. Package code can detect tracing, stay dormant, exploit a runtime vulnerability, or behave differently outside the harness. Profiles are unsigned JSON. `validate` checks structure, internal consistency, and retained raw evidence integrity; it does not verify who produced the artifacts.

Read [the threat model](docs/THREAT_MODEL.md) and [the limitations](docs/LIMITATIONS.md) before using capture as part of a security decision.

## Documentation

1. [User guide](docs/USER_GUIDE.md) explains the tool without requiring security expertise.
2. [Technical reference](docs/TECHNICAL_REFERENCE.md) documents the pipeline, data model, comparability rules, and failure behavior.
3. [Platform support](docs/PLATFORM_SUPPORT.md) describes Linux, macOS, and Windows support.
4. [Evidence model](docs/EVIDENCE_MODEL.md) defines retained artifacts, line references, validation, and privacy.
5. [Acquisition proxy](docs/ACQUISITION_PROXY.md) defines registry egress enforcement and its residual risks.
6. [Provenance and releases](docs/PROVENANCE_AND_RELEASES.md) defines trusted bundles, proof collection, SBOMs, signing, and disabled publication controls.
7. [Review rules](docs/RULES.md) defines the versioned rule registry, precedence, and attribution boundaries.
8. [Resource boundaries and repeatability](docs/RESOURCE_AND_REPEATABILITY.md) defines exhaustion outcomes, cleanup, and the ten-run semantic stability gate.
9. [Canary, import, and sinkhole observations](docs/CANARY_IMPORT_AND_SINKHOLE.md) defines the optional observation modes and their privacy boundary.
10. [Split-privilege dependency review automation](docs/DEPENDENCY_REVIEW_AUTOMATION.md) defines the unprivileged capture and privileged comment boundary.
11. [Security audit](docs/SECURITY_AUDIT.md) records the latest review, fixes, scan evidence, and remaining risks.
12. [Architecture](docs/ARCHITECTURE.md) describes component boundaries.
13. [Threat model](docs/THREAT_MODEL.md) lists assets, hostile inputs, controls, and residual risk.
14. [Limitations](docs/LIMITATIONS.md) states what BehaviorLock cannot observe or prove.
15. [Roadmap](ROADMAP.md) contains the release gates.
16. [Security policy](SECURITY.md) explains private vulnerability reporting.
17. [Operator runbooks](docs/runbooks/README.md) define disposable capture, evidence, failures, verification, rollback, and cleanup.
18. [Inert benchmark report](benchmark/REPORT.md) records exact fixture expectations and separates them from projected historical coverage.
19. [Usability evidence](docs/USABILITY_METRICS.md) defines local, non-telemetry product measures.
20. [Incident analysis template](docs/templates/INCIDENT_ANALYSIS.md) defines disclosure, redaction, uncertainty, and publication approval.

## Development

```bash
make check
make build
make benchmark
make usability
```

Docker integration runs separately:

```bash
make integration
```

The protected `ci-required` job runs race enabled tests, shell checks, schema checks, vulnerability scanning, DCO verification, the inert usability journey, and the hardened Docker integration. CodeQL and scheduled parser fuzzing run in separate workflows.

`scripts/current-release-report.sh` queries GitHub for the exact selected commit and prints all 14 named proof states. A blocked report exits `1`. The checked-in [status snapshot](reports/RELEASE_GATE_STATUS.md) is descriptive only and cannot authorize a release or launch.

## Project status

BehaviorLock is a public experiment with no tagged release. The parser and comparison core are usable now. The capture backend remains experimental until every adversarial gate in [ROADMAP.md](ROADMAP.md) passes and trusted profiles have verifiable provenance. The acquisition proxy has hosted draft-branch proof, but gate 6 still requires maintainer review and merge to protected `main`.

Profiles and reports can retain sensitive paths and package controlled strings. Review every artifact before attaching it to an issue, publishing it, or committing it.

## Contributing and security reports

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Human commits require Developer Certificate of Origin 1.1 signoff. Security vulnerabilities belong in [GitHub private vulnerability reporting](https://github.com/kiranmagic7/behaviorlock/security/advisories/new), not public issues.

## Name and prior work

This repository uses the owner qualified name `kiranmagic7/behaviorlock`. It is independent of the earlier `christian140903-sudo/behaviorlock` project, which checks AI agent compatibility. The projects have different purposes and no affiliation.

BehaviorLock does not claim ownership of the phrase "Bill of Behavior" and does not present itself as a standard. [ORIGINS.md](docs/ORIGINS.md) records adjacent projects and the boundaries of this implementation.

## License

Apache License 2.0. Contributions are accepted under the same license through Developer Certificate of Origin 1.1 signoff.
