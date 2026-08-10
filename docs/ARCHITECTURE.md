# Architecture

BehaviorLock has four boundaries: input validation, observation, normalization, and comparison.

## Input validation

The first release accepts only an npm registry name followed by an exact semantic version. The parser rejects ranges, tags, aliases, URLs, Git references, local paths, whitespace, control characters, Unicode lookalikes, and leading option syntax before Docker starts.

Docker commands are created as argument arrays. User input is never placed inside a host shell command, container name, image name, mount, environment variable name, or Docker option.

The local runner tag is resolved to one validated Docker content ID before capture. Metadata inspection and preparation use that immutable ID. The committed package filesystem is also executed by the content ID returned from `docker commit`, not by its temporary tag.

## Observation

Capture has two disposable container phases.

The preparation phase installs an exact top level package version with lifecycle scripts disabled and records the generated dependency lock digest. It runs as uid `65532`, uses Docker network mode `none`, and receives no host mounts, home directory, npm configuration, Git configuration, SSH material, cloud credentials, repository token, or Docker socket. Npm is pinned to a loopback relay whose only destination is a private Unix socket in a randomly named Docker volume.

An unprivileged proxy sidecar owns that socket and joins a separate egress network. It accepts CONNECT only for `registry.npmjs.org:443`, rejects nonpublic DNS answers, and dials the validated address directly. The lockfile validator then rejects Git, local, linked, credentialed, alternate-port, and off-registry dependency sources. The profile records this policy and the immutable proxy image ID.

The execution phase starts from the prepared filesystem. It runs either the default install lifecycle or the explicitly selected resolved-package import. Networking is disabled by default. If the inert sinkhole is selected, execution shares only the sinkhole container's unrouted loopback namespace. The root filesystem is read only and writable locations are bounded temporary filesystems. A root supervisor owns the trace channel while the package command runs as uid `65532`. After dropping all capabilities, the container adds only `SETUID`, `SETGID`, and `SYS_PTRACE` so the supervisor can perform the identity transition and trace inside the container PID namespace. The package process has zero effective capabilities. Docker's default seccomp policy remains intact.

Each capture creates distinct, nonsecret canary values for declared disposable file and environment locations. Exact values are converted to stable identifiers only when visible on an already observed path, process argument, or bounded sinkhole request. The optional sinkhole returns fixed loopback DNS, HTTP, and TCP responses, records bounded counts and matching canary identifiers, and discards request bytes.

`strace` writes timestamped per-process files into a root owned mode `0700` temporary filesystem that package code cannot access. The trusted runner prefixes each retained line with the numeric trace-file process identifier and merges the files by the tracer timestamp before assembling the envelope. The selected calls cover path and descriptor file activity, process creation and execution, anonymous memory files, process inspection, socket and endpoint activity, and timing probes. Package output is separated from the trace envelope. Root owned start and end sentinel reads, an empty tracer diagnostic channel, and a completion footer establish basic channel integrity. Missing evidence, tracer diagnostics, timeout, truncation, or malformed completion evidence makes the profile incomplete.

## Normalization

The parser has byte, line, behavior, process, descriptor, and pending-syscall limits. It rejects invalid UTF 8, reassembles matching unfinished/resumed calls, and rejects inconsistent or incomplete continuation state. It normalizes only known disposable roots at exact path boundaries and selected process identifiers:

1. `/work` becomes `$WORK`
2. `/home/scanner` becomes `$HOME`
3. selected npm temporary roots become `$TMP`
4. numeric `/proc` identifiers become `$PID`

Successful open, socket, duplicate, close, and child-creation calls update bounded descriptor and lineage state separately for each process. This allows descriptor-only activity to receive a normalized path or endpoint when evidence supports the attribution. Missing attribution remains explicit as `fd:unknown`; it is never guessed.

Behavior records are deduplicated, counted, sorted, and assigned content-derived semantic identifiers. They may retain up to eight capture-local runtime contexts containing process, parent, descriptor, and attribution data. Bounded sequences retain first-seen normalized behavior order for selected anchor-and-action observations within one process lineage; runtime identifiers do not enter sequence identity. A separate mode `0600` raw evidence artifact is retained. Each normalized behavior carries up to eight references containing the artifact SHA 256, raw line number, and exact raw line SHA 256. Validation checks both the complete artifact and every reference before a profile can be compared.

The semantic digest excludes duration, evidence artifact metadata, line references, observation counts, and runtime process/parent/descriptor context, but retains runner identity, subject, observation policy, coverage, result, and normalized behavior meaning. Repeated captures can therefore have different evidence coordinates or runtime identifiers without changing the meaning digest.

## Comparison

Two complete profiles for the same package, phase, and equivalent runner environment are compared as deterministic sets. Lifecycle and import profiles are never mixed. External unverified traces require explicit caller acknowledgement. Added observations receive fixed rule identifiers and review levels. Added and removed sequences are reported as ordering context. Removed observations are retained without being interpreted as safer.

Ordinary profiles declare `attestation: none`. Environment fields and retained evidence allow consistency and comparability checks but are not authenticated. The protected trusted-profile workflow can package two reviewed profiles and their evidence into one GitHub-attested bundle. Verification binds that bundle to its repository, workflow, protected source commit, hosted runner, runner image, and acquisition policy before cross-workflow use. It does not upgrade arbitrary profiles or contributor artifacts into trusted evidence.

Dependency review uses a different, lower-trust path. A `pull_request` job with a read-only token checks out only the trusted base, reads both manifests through the GitHub API, and captures exact public-registry versions itself. A separate default-branch `workflow_run` job holds comment permission, never executes the downloaded artifact, independently verifies every identity and evidence boundary, and regenerates sanitized Markdown. These artifacts remain untrusted review inputs and can never satisfy the protected trusted-profile or release proof gates.

The report summary is:

1. No added behavior or sequence: `reviewRequired: false` and `highestReviewLevel: none`
2. Any added behavior: `reviewRequired: true` with the highest deterministic behavior review level
3. A sequence-only addition: `reviewRequired: true` and `highestReviewLevel: none`; no level is invented for ordering context
4. Incomplete or evidence-mismatched profile: error

The CLI threshold controls only its exit code. It does not rewrite the report or issue a package verdict.

## Stable extension points

Contributors can add syscall parsers, normalization rules, report formats, policy rules, and package ecosystems without changing the Docker supervisor. Sandbox changes require a threat model update and maintainer security review.
