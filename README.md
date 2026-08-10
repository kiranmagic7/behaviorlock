# BehaviorLock

BehaviorLock shows how the observed install behavior of an npm package changes between two exact versions.

Source review and vulnerability databases answer important questions about a dependency update. BehaviorLock asks another one: did the new version begin reading a credential path, starting a shell, changing files, or attempting a network connection when its install scripts ran?

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
| Observed environment | Linux container install lifecycle |
| CLI build and unit tests | Linux and macOS |
| Full Docker integration | GitHub hosted Linux runner |
| Native Windows or macOS tracing | Not supported |
| Evidence integrity | Raw trace retained separately and verified by digest and line references |
| Profile authenticity | Unsigned, not attested |
| Tagged release | None |

## What it observes

The current parser records a bounded subset of:

1. File reads, writes, creation, deletion, renaming, and permission changes
2. Executable launches and up to 32 visible arguments
3. Network connection attempts
4. Whether an observed call succeeded, failed, or was blocked

The capture path exercises npm `preinstall`, `install`, and `postinstall` scripts through `npm rebuild`. It does not observe normal application runtime behavior.

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
run lifecycle offline under strace
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

Preparation and execution are separate. Preparation needs registry access and runs with lifecycle scripts disabled. Execution starts from the prepared filesystem, has no network, uses a read only root filesystem, receives no host mounts or inherited credentials, and runs package code as uid `65532` with zero effective capabilities.

The preparation network is still a risk. Package metadata and transitive dependency metadata can influence what npm fetches. Use capture only on a disposable runner that cannot reach sensitive private networks or cloud metadata.

## Try the comparison without Docker

Go 1.23 or newer is required.

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
bin/behaviorlock doctor

bin/behaviorlock capture \
  --experimental \
  --package is-number@7.0.0 \
  --timeout 2m \
  --output is-number.profile.json
```

`--experimental` is mandatory. The command records the exact runner image ID, architecture, Node version, npm version, `strace` version, package registry integrity, and dependency lock digest. It also retains `is-number.profile.json.evidence.strace` unless `--evidence-output` selects another path. Docker execution uses immutable image IDs after resolution so a mutable local tag cannot silently change the captured environment.

Do not capture an unknown package on a machine that contains valuable data, credentials, trusted workloads, or access to private infrastructure.

## Compare two captured versions

Both profiles must describe the same package and use the same runner image ID, architecture, Node version, npm version, `strace` version, network mode, sandbox profile, and coverage scope. Their companion evidence files must be present beside the profiles, or supplied with `--baseline-evidence` and `--candidate-evidence`.

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
| `BL200` | High | New network connection attempt during offline execution |
| `BL300` | High | New shell, downloader, or remote access process |
| `BL301` | Medium | New executable process |
| `BL400` | High | New mutation outside disposable work and temporary roots |
| `BL401` | Medium | New mutation inside a disposable writable root |
| `BL402` | Medium | New deletion or permission change |
| `BL500` | Low | New file read or metadata inspection |

The report exposes `reviewRequired` and `highestReviewLevel`; it does not issue a package verdict. The CLI threshold controls only the process exit code. No observed addition, or an exit code of `0`, authenticates the profiles, establishes full coverage, or proves safety.

## Command reference

```text
behaviorlock doctor
behaviorlock capture --experimental --package name@1.2.3 --output profile.json [--evidence-output raw.strace]
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
4. Offline lifecycle execution and a read only root filesystem
5. Bounded memory, CPU, processes, descriptors, temporary storage, output, and wall clock time
6. A root owned trace directory that package code cannot read or modify
7. Immutable Docker content IDs for the runner and prepared package filesystem
8. Required trace sentinels, completion evidence, and an empty tracer diagnostic channel
9. Separate mode `0600` evidence artifacts whose full digest and referenced line digests are verified before comparison

Containers still share a kernel. Package code can detect tracing, stay dormant, exploit a runtime vulnerability, or behave differently outside the harness. Profiles are unsigned JSON. `validate` checks structure, internal consistency, and retained raw evidence integrity; it does not verify who produced the artifacts.

Read [the threat model](docs/THREAT_MODEL.md) and [the limitations](docs/LIMITATIONS.md) before using capture as part of a security decision.

## Documentation

1. [User guide](docs/USER_GUIDE.md) explains the tool without requiring security expertise.
2. [Technical reference](docs/TECHNICAL_REFERENCE.md) documents the pipeline, data model, comparability rules, and failure behavior.
3. [Platform support](docs/PLATFORM_SUPPORT.md) describes Linux, macOS, and Windows support.
4. [Evidence model](docs/EVIDENCE_MODEL.md) defines retained artifacts, line references, validation, and privacy.
5. [Security audit](docs/SECURITY_AUDIT.md) records the latest review, fixes, scan evidence, and remaining risks.
6. [Architecture](docs/ARCHITECTURE.md) describes component boundaries.
7. [Threat model](docs/THREAT_MODEL.md) lists assets, hostile inputs, controls, and residual risk.
8. [Limitations](docs/LIMITATIONS.md) states what BehaviorLock cannot observe or prove.
9. [Roadmap](ROADMAP.md) contains the release gates.
10. [Security policy](SECURITY.md) explains private vulnerability reporting.

## Development

```bash
make check
make build
```

Docker integration runs separately:

```bash
make integration
```

The protected `ci-required` job runs race enabled tests, shell checks, schema checks, vulnerability scanning, DCO verification, and the hardened Docker integration. CodeQL and scheduled parser fuzzing run in separate workflows.

## Project status

BehaviorLock is a public experiment with no tagged release. The parser and comparison core are usable now. The capture backend remains experimental until every adversarial gate in [ROADMAP.md](ROADMAP.md) passes, trusted profiles have verifiable provenance, and the acquisition network boundary is stronger.

Profiles and reports can retain sensitive paths and package controlled strings. Review every artifact before attaching it to an issue, publishing it, or committing it.

## Contributing and security reports

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Human commits require Developer Certificate of Origin 1.1 signoff. Security vulnerabilities belong in [GitHub private vulnerability reporting](https://github.com/kiranmagic7/behaviorlock/security/advisories/new), not public issues.

## Name and prior work

This repository uses the owner qualified name `kiranmagic7/behaviorlock`. It is independent of the earlier `christian140903-sudo/behaviorlock` project, which checks AI agent compatibility. The projects have different purposes and no affiliation.

BehaviorLock does not claim ownership of the phrase "Bill of Behavior" and does not present itself as a standard. [ORIGINS.md](docs/ORIGINS.md) records adjacent projects and the boundaries of this implementation.

## License

Apache License 2.0. Contributions are accepted under the same license through Developer Certificate of Origin 1.1 signoff.
