# Technical reference

## Inert regression corpus

`benchmark/manifest.json` is a strict, bounded contract for offline hand-written traces. The benchmark runner confines fixture paths to regular non-symlink files under `benchmark/corpus`, constructs external-unverified profiles in memory, recomputes diffs with the production parser and rule engine, and requires exact sets of added behavior types, rule identifiers, and highest review level. Unknown fields, path escapes, duplicate IDs, unsafe citations, expectation drift, and unsupported reconstruction states fail closed.

The JSON and Markdown report are deterministic and contain no current timestamp. `scripts/check-benchmark.sh` runs the report twice, compares bytes, and checks the committed Markdown report. Observed fixture results and projected historical coverage are separate types. A projection cannot become an executed result through formatting or aggregation.

## Release gate reporting

`cmd/release-gate` remains the binary authorization check. `cmd/release-report` uses the same strict configuration and evidence model but enumerates all 14 gate states so operators can see every missing, skipped, failed, stale, mismatched, duplicated, or unexpected proof. It prints a report even when blocked and exits `1` unless every gate is satisfied for the exact repository and commit.

`scripts/current-release-report.sh` collects check-run evidence through GitHub’s API, never accepts a pull-request-supplied proof file, and then runs the local reporter. Reports are descriptive. They cannot create a tag, publish an image, approve a Marketplace listing, or satisfy gate 14.

## Usability verification

`scripts/usability-check.sh` builds both user-facing binaries from a clean checkout, runs the inert demo, validates evidence, proves tamper rejection, proves byte-identical replay, checks report interpretation fields, runs the benchmark, and proves a 0-of-14 release report remains blocked. Hosted Docker integration separately proves disposable Linux capture and cleanup because offline trace replay cannot establish container containment.

## Scope

BehaviorLock `0.1.0-dev` compares selected Linux system calls observed during the same bounded phase for two exact versions of one public registry package. Offline install lifecycle execution is the default. Import and sinkhole observation are explicit experiments.

The system has four main boundaries:

1. Package specification validation
2. Acquisition and preparation
3. Selected-phase execution and tracing
4. Normalization, validation, and comparison

## Components

| Component | Responsibility |
| --- | --- |
| `internal/npm` | Parse exact npm package specifications and generate package URLs |
| `internal/capture` | Construct bounded Docker argument arrays and orchestrate capture |
| `runner` | Prepare package filesystems and run lifecycle or resolved import phases under `strace` |
| `internal/trace` | Parse bounded trace input into normalized behaviors |
| `internal/model` | Validate profiles, normalize behavior, and compute stable digests |
| `internal/compare` | Check profile compatibility, calculate changes, and assign review rules |
| `internal/cli` | Expose commands, exit codes, and report formats |
| `schemas` | Publish versioned JSON contracts for profiles and diffs |

## Input contract

Capture accepts a public npm package name followed by one exact semantic version.

Accepted examples:

```text
lodash@4.17.21
@scope/package@1.2.3
package@1.0.0-rc.1
```

Ranges, tags, aliases, URLs, Git references, local paths, whitespace, control characters, Unicode lookalikes, and leading option syntax are rejected before Docker starts.

## Capture phases

### Runner resolution

The local tag `behaviorlock-runner:dev` is inspected once to obtain its Docker content ID and architecture. All later metadata and preparation commands use the immutable content ID, not the mutable tag. The profile records both the human readable tag and the content ID.

### Preparation

Preparation runs as uid `65532` with lifecycle scripts disabled and Docker network mode `none`. It receives no host mounts, Docker socket, home directory, npm configuration, Git configuration, SSH data, cloud credentials, or repository tokens. Docker client proxy configuration is replaced with an exact loopback proxy address.

The loopback relay can reach only a randomly named private Unix socket. An unprivileged sidecar proxy accepts CONNECT only for `registry.npmjs.org:443`, rejects any DNS answer set containing a nonpublic address, and dials the selected validated IP directly. The lockfile inventory rejects nonregistry acquisition sources. The phase still has no portable overlay disk quota and shares the Docker host kernel, so it belongs on a disposable runner.

Preparation records:

1. Top level npm registry integrity
2. SHA 256 of the generated dependency lockfile
3. Runner image content ID and architecture
4. Node, npm, and `strace` versions
5. Acquisition network mode, policy version, allowed authority, and immutable proxy image ID
6. A bounded CommonJS, ESM, or unsupported import-entry-point plan

The stopped preparation container is committed to a random temporary tag. Docker returns the committed content ID, and execution uses that immutable ID.

### Execution

Execution uses:

1. Docker network mode `none` by default, or an opt-in shared namespace with an inert responder that itself has network mode `none`
2. A read only root filesystem
3. No host mounts or host namespaces
4. Bounded tmpfs mounts for work, temporary data, home, and trace storage
5. Memory, CPU, process, descriptor, shared memory, and wall clock limits
6. Docker's default seccomp policy
7. `no-new-privileges`

The supervisor begins as root and retains only `SETUID`, `SETGID`, and `SYS_PTRACE` after all capabilities are dropped. Package code runs as uid `65532` with zero effective capabilities.

The trace directory is owned by root with mode `0700`. Package code cannot read, erase, or replace trace files.

Each capture generates distinct nonsecret decoy values for declared file and environment locations. Generated values are not stored in profile metadata. Exact matches are converted to stable canary identifiers only when visible in an already observed filesystem target, process argument, or bounded sinkhole request.

Lifecycle execution invokes `npm rebuild` for `preinstall`, `install`, and `postinstall`. Import execution resolves and loads the package entry point as CommonJS or ESM. Import profiles use a different phase and coverage scope; unresolved and unsupported entry points produce an explicit `unsupported` result.

### Completion evidence

A trusted envelope requires:

1. A versioned trace header
2. A successful read of the start sentinel
3. At least one recognized event
4. A successful read of the end sentinel
5. A valid completion footer and child exit code
6. No `strace` diagnostics
7. No timeout or output truncation

Any missing condition produces an incomplete result and exit code `2`.

## Normalized behavior

Each behavior contains:

| Field | Meaning |
| --- | --- |
| `type` | File, process, or network behavior category |
| `operation` | Normalized action such as read, write, or exec |
| `target` | Normalized path, executable, or endpoint |
| `arguments` | Bounded visible process arguments |
| `outcome` | `success`, `blocked`, `failed`, or `unknown` |
| `errno` | Visible Linux error name when present |
| `sensitive` | Whether the target matches a common credential path |
| `canaryIds` | Stable identifiers for exact generated canaries visible on an approved surface |
| `count` | Number of equivalent raw observations |
| `id` | Content-derived semantic behavior identifier |
| `evidence` | One to eight raw artifact, line number, and exact line digest references |
| `sourceSyscall` | Original syscall family |
| `runtime` | Up to eight bounded process, parent, descriptor, and attribution contexts |

Profiles can also contain bounded observed-order sequences. Each sequence references two through 32 stable behavior IDs from one root process lineage. Runtime PIDs and descriptors are excluded from sequence identity. Sequences describe order only and do not classify intent.

Disposable roots are normalized only at path boundaries:

```text
/work/file                 becomes $WORK/file
/workspace/file            stays /workspace/file
/home/scanner/.npmrc       becomes $HOME/.npmrc
/home/scanner-backup/file  stays /home/scanner-backup/file
```

## Profile validation

`validate` checks:

1. Schema and phase-neutral kind versions
2. Exact package name, version, and package URL agreement
3. Bounded UTF 8 text without control characters
4. Valid SHA 256 content IDs and digests
5. Valid SHA 512 npm integrity evidence
6. Consistent phase, capture mode, coverage, lifecycle, import, sinkhole, and result state
7. Declared canary identifiers and references without generated values
8. Behavior and sequence type, argument, count, semantic ID, evidence reference, and outcome limits
9. The complete companion evidence artifact digest and byte size
10. Every referenced raw line digest and line boundary
11. No trailing JSON values or unknown fields

Validation proves that the supplied schema v3 profile and companion raw artifact agree. Profiles have `attestation: none`, so successful validation does not establish who created either artifact or whether the capture provenance fields are true. Schema v1 and v2 files remain published for historical decoding, but the current CLI rejects cross-version comparison and asks the caller to regenerate old profiles.

## Stable digest

The stable profile digest includes subject identity, tool identity, phase, capture environment, observation policy, result state, normalized behaviors, observed sequences, sinkhole policy, and visible canary movement.

It excludes duration, evidence artifact metadata, evidence references, repeated event counts, sinkhole request counts, runtime process/parent/descriptor context, unstable temporary paths, and raw trace line numbers. This makes repeated captures comparable while preserving fields that can change the meaning of a result.

## Comparison contract

Profiles must:

1. Be structurally valid, evidence-verified, and complete
2. Describe the same npm package
3. Use the same trace integrity mode
4. Use the same runner image reference, resolved image ID, and architecture
5. Use the same Node, npm, and `strace` versions
6. Use the same lifecycle, import, or external phase
7. Use the same network mode, sandbox profile, coverage scope, and observation policy

Lifecycle and import profiles are never compared or merged silently. External traces require explicit `--allow-external` acknowledgement.

The comparator calculates added and removed behavior keys and sequence identities. Added behavior is classified by deterministic rules in `internal/compare`; removed behavior and all sequence changes remain uninterpreted evidence context. An added sequence makes `reviewRequired` true, but a sequence-only change leaves `highestReviewLevel` at `none` because BehaviorLock does not assign an invented level to ordering.

### Review rules

| Rule | Level | Observation |
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

`BL600` matches `/.dockerenv`, `/run/.containerenv`, normalized `/proc/$PID/cgroup`, `/proc/self/status`, `/proc/self/mountinfo`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/uptime`, and `/sys/class/dmi` or a descendant. Exact or path-boundary matching prevents similarly named files from receiving the rule. Sensitive-path classification takes precedence as `BL100`. A match is an observation for review: diagnostic and platform-detection code can legitimately read these paths, so it does not prove sandbox evasion or malicious intent. Ptrace and timing observations use `BL304` and `BL601`, preserving the established meaning of both `BL500` and `BL600`.

The complete versioned registry, precedence rules, optional `consistent with` ATT&CK context, and attribution notes are in [review rules](RULES.md).

### Descriptor and process context

The parser keeps bounded descriptor tables separately for each observed process. Successful open, socket, duplicate, close, close-on-exec, process-exit, and child-creation calls update those tables. Descriptor-backed mutation, enumeration, listening, and fileless execution can therefore point to a normalized path or endpoint. If attribution is unavailable, the target is the explicit value `fd:unknown`; the parser never invents a path. This is bounded review context, not a complete model of every kernel descriptor-sharing edge case.

Each behavior can retain bounded runtime context for review, including the observed process, its known parent, the descriptor number, and whether attribution was direct, descriptor-derived, or unknown. These capture-local identifiers do not alter behavior identity or the stable digest. Process lineage, descriptor context, event counts, and evidence coordinates may differ between semantically equivalent runs.

Numeric process paths normalize at a path boundary, so `/proc/123/status` becomes `/proc/$PID/status` while a lookalike such as `/proc/123-backup/status` stays unchanged. Earlier development profiles affected by the old replacement bug can contain a different target and stable digest. Recapture both versions with the same BehaviorLock commit before using such profiles in a comparison.

## CLI commands

### `doctor`

Checks that Docker is available and the requested `--runner` reference resolves to a valid content ID. Implicit or explicit `latest` references are rejected.

### `capture`

Acquires an exact public npm version and creates a trusted harness profile. It requires `--experimental`.

### `profile`

Converts caller supplied raw `strace` input into an `external-unverified` profile.

### `compare`

Compares two compatible profiles and writes JSON, text, or Markdown.

### `validate`

Checks one profile and its companion raw evidence, then prints the stable digest. It explicitly states that artifact integrity was verified while signer authenticity was not.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Operation completed and the comparison threshold was not reached |
| `1` | Added behavior reached the selected comparison threshold |
| `2` | Input, evidence, sandbox, parser, or runtime failure |

## Resource limits

The trace parser and evidence verifier accept at most 64 MiB of raw trace data, 256 KiB per parsed line, 250,000 recognized behaviors, and eight retained evidence references per normalized behavior. Profile JSON is limited to 32 MiB. Docker adds separate process, memory, CPU, file descriptor, single-file, shared-memory, tmpfs, output, and wall-clock limits. An authoritative Docker OOM state produces `resource_exhausted`; timeout, cancellation, signal-style exit, truncation, and tracer failure remain distinct incomplete outcomes. See [resource boundaries and repeatability](RESOURCE_AND_REPEATABILITY.md).

## Reproducibility

Comparable profiles require the same execution environment, but identical environments do not guarantee identical package behavior. Packages can use randomness, time, architecture checks, dependency variation, or tracing detection.

The dependency lock digest records graph variation. It does not prevent it. Repeat important captures and inspect disagreement rather than automatically approving a new baseline.

## Development verification

`make check` runs formatting, `go vet`, race enabled tests, shell syntax, ShellCheck, Actionlint, JSON checks, and deterministic inert benchmark verification. `make usability` runs the build, replay, evidence-tamper, report-interpretation, fail-closed release-report, and temporary-file cleanup journey.

Hosted workflows add vulnerability scanning, CodeQL, scheduled fuzzing, DCO enforcement, the clean-checkout usability journey, and hardened Docker integration. The integration includes inert adversarial, resource, network, sinkhole, and tracer-failure fixtures. The Docker job is the disposable Linux capture usability proof; the offline usability job does not substitute for it.
