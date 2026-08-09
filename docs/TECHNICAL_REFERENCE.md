# Technical reference

## Scope

BehaviorLock `0.1.0-dev` compares selected Linux system calls observed while npm install lifecycle scripts execute for two exact versions of the same public registry package.

The system has four main boundaries:

1. Package specification validation
2. Acquisition and preparation
3. Offline execution and tracing
4. Normalization, validation, and comparison

## Components

| Component | Responsibility |
| --- | --- |
| `internal/npm` | Parse exact npm package specifications and generate package URLs |
| `internal/capture` | Construct bounded Docker argument arrays and orchestrate capture |
| `runner` | Prepare package filesystems and run lifecycle scripts under `strace` |
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

The stopped preparation container is committed to a random temporary tag. Docker returns the committed content ID, and execution uses that immutable ID.

### Execution

Execution uses:

1. Docker network mode `none`
2. A read only root filesystem
3. No host mounts or host namespaces
4. Bounded tmpfs mounts for work, temporary data, home, and trace storage
5. Memory, CPU, process, descriptor, shared memory, and wall clock limits
6. Docker's default seccomp policy
7. `no-new-privileges`

The supervisor begins as root and retains only `SETUID`, `SETGID`, and `SYS_PTRACE` after all capabilities are dropped. Package code runs as uid `65532` with zero effective capabilities.

The trace directory is owned by root with mode `0700`. Package code cannot read, erase, or replace trace files.

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
| `count` | Number of equivalent raw observations |
| `id` | Content-derived semantic behavior identifier |
| `evidence` | One to eight raw artifact, line number, and exact line digest references |
| `sourceSyscall` | Original syscall family |

Disposable roots are normalized only at path boundaries:

```text
/work/file                 becomes $WORK/file
/workspace/file            stays /workspace/file
/home/scanner/.npmrc       becomes $HOME/.npmrc
/home/scanner-backup/file  stays /home/scanner-backup/file
```

## Profile validation

`validate` checks:

1. Schema and kind versions
2. Exact package name, version, and package URL agreement
3. Bounded UTF 8 text without control characters
4. Valid SHA 256 content IDs and digests
5. Valid SHA 512 npm integrity evidence
6. Consistent capture mode, coverage, lifecycle, and result state
7. Behavior type, argument, count, semantic ID, evidence reference, and outcome limits
8. The complete companion evidence artifact digest and byte size
9. Every referenced raw line digest and line boundary
10. No trailing JSON values or unknown fields

Validation proves that the supplied schema v2 profile and companion raw artifact agree. Profiles have `attestation: none`, so successful validation does not establish who created either artifact or whether the capture provenance fields are true. Schema v1 files remain published for historical decoding, but the current CLI rejects cross-version comparison and asks the caller to regenerate old profiles.

## Stable digest

The stable profile digest includes subject identity, tool identity, capture environment, result state, and the normalized behavior set.

It excludes duration, evidence artifact metadata, evidence references, repeated event counts, process IDs, unstable temporary paths, and raw trace line numbers. This makes repeated captures comparable while preserving fields that can change the meaning of a result.

## Comparison contract

Profiles must:

1. Be structurally valid, evidence-verified, and complete
2. Describe the same npm package
3. Use the same trace integrity mode
4. Use the same runner image reference, resolved image ID, and architecture
5. Use the same Node, npm, and `strace` versions
6. Use the same network mode, sandbox profile, and coverage scope

External traces require explicit `--allow-external` acknowledgement.

The comparator calculates added and removed behavior keys. Added behavior is classified by deterministic rules in `internal/compare`.

### Review rules

| Rule | Level | Observation |
| --- | --- | --- |
| `BL100` | Critical | New access to a common credential or secret path |
| `BL200` | High | New network connection attempt during offline execution |
| `BL300` | High | New shell, downloader, or remote access process |
| `BL301` | Medium | New executable process |
| `BL400` | High | New mutation outside disposable work and temporary roots |
| `BL401` | Medium | New mutation inside a disposable writable root |
| `BL402` | Medium | New deletion or permission change |
| `BL500` | Low | New file read or metadata inspection |
| `BL600` | Medium | New access to a path commonly used to detect containers or tracing |

`BL600` matches `/.dockerenv`, `/run/.containerenv`, normalized `/proc/$PID/cgroup`, `/proc/self/status`, `/proc/self/mountinfo`, `/proc/cpuinfo`, `/proc/meminfo`, `/proc/uptime`, and `/sys/class/dmi` or a descendant. Exact or path-boundary matching prevents similarly named files from receiving the rule. Sensitive-path classification takes precedence as `BL100`. A match is an observation for review: diagnostic and platform-detection code can legitimately read these paths, so it does not prove sandbox evasion or malicious intent. This rule currently covers path-based observations only; `ptrace` and timing syscalls remain outside the parser's selected coverage.

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

The trace parser and evidence verifier accept at most 64 MiB of raw trace data, 256 KiB per parsed line, 250,000 recognized behaviors, and eight retained evidence references per normalized behavior. Profile JSON is limited to 32 MiB. Docker adds separate process, memory, CPU, file descriptor, shared memory, tmpfs, output, and wall clock limits.

## Reproducibility

Comparable profiles require the same execution environment, but identical environments do not guarantee identical package behavior. Packages can use randomness, time, architecture checks, dependency variation, or tracing detection.

The dependency lock digest records graph variation. It does not prevent it. Repeat important captures and inspect disagreement rather than automatically approving a new baseline.

## Development verification

`make check` runs formatting, `go vet`, race enabled tests, shell syntax, ShellCheck, Actionlint, and JSON checks.

Hosted workflows add vulnerability scanning, CodeQL, scheduled fuzzing, DCO enforcement, and hardened Docker integration. The integration includes an inert adversarial fixture and a simulated tracer diagnostic that must fail closed.
