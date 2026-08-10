# Architecture

BehaviorLock has four boundaries: input validation, observation, normalization, and comparison.

## Input validation

The first release accepts only an npm registry name followed by an exact semantic version. The parser rejects ranges, tags, aliases, URLs, Git references, local paths, whitespace, control characters, Unicode lookalikes, and leading option syntax before Docker starts.

Docker commands are created as argument arrays. User input is never placed inside a host shell command, container name, image name, mount, environment variable name, or Docker option.

The local runner tag is resolved to one validated Docker content ID before capture. Metadata inspection and preparation use that immutable ID. The committed package filesystem is also executed by the content ID returned from `docker commit`, not by its temporary tag.

## Observation

Capture has two disposable container phases.

The preparation phase installs an exact top level package version with lifecycle scripts disabled and records the generated dependency lock digest. It runs as uid `65532` and receives no host mounts, home directory, npm configuration, Git configuration, SSH material, cloud credentials, repository token, or Docker socket. Standard uppercase and lowercase proxy variables are explicitly empty, which prevents Docker client proxy settings from being injected. Preparation still has direct registry network access, so package and transitive dependency metadata can influence outbound fetches. It belongs on a disposable runner with no route to sensitive private services.

The execution phase starts from the prepared filesystem. Networking is disabled. The root filesystem is read only and writable locations are bounded temporary filesystems. A root supervisor owns the trace channel while the package command runs as uid `65532`. After dropping all capabilities, the container adds only `SETUID`, `SETGID`, and `SYS_PTRACE` so the supervisor can perform the identity transition and trace inside the container PID namespace. The package process has zero effective capabilities. Docker's default seccomp policy remains intact.

`strace` writes into a root owned mode `0700` temporary filesystem that package code cannot access. It follows a selected set of file, process, and network syscalls. Package output is separated from the trace envelope. Root owned start and end sentinel reads, an empty tracer diagnostic channel, and a completion footer establish basic channel integrity. Missing evidence, tracer diagnostics, timeout, truncation, or malformed completion evidence makes the profile incomplete.

## Normalization

The parser has byte, line, and behavior limits. It rejects invalid UTF 8 and unfinished syscalls. It normalizes only known disposable roots at exact path boundaries and selected process identifiers:

1. `/work` becomes `$WORK`
2. `/home/scanner` becomes `$HOME`
3. selected npm temporary roots become `$TMP`
4. numeric `/proc` identifiers become `$PID`

Behavior records are deduplicated, counted, sorted, and assigned content-derived semantic identifiers. A separate mode `0600` raw evidence artifact is retained. Each normalized behavior carries up to eight references containing the artifact SHA 256, raw line number, and exact raw line SHA 256. Validation checks both the complete artifact and every reference before a profile can be compared.

The semantic digest excludes duration, evidence artifact metadata, line references, and observation counts, but retains runner identity, subject, coverage, result, and normalized behavior meaning. Repeated captures can therefore have different evidence coordinates without changing the meaning digest.

## Comparison

Two complete profiles for the same package and equivalent runner environment are compared as deterministic sets. External unverified traces require explicit caller acknowledgement. Added observations receive fixed rule identifiers and review levels. Removed observations are retained without being interpreted as safer.

Profiles declare `attestation: none`. Environment fields and retained evidence allow consistency and comparability checks but are not authenticated. A future signed provenance format is a separate release gate.

The report summary is:

1. No added behavior: `reviewRequired: false` and `highestReviewLevel: none`
2. Any added behavior: `reviewRequired: true` with the highest deterministic review level
3. Incomplete or evidence-mismatched profile: error

The CLI threshold controls only its exit code. It does not rewrite the report or issue a package verdict.

## Stable extension points

Contributors can add syscall parsers, normalization rules, report formats, policy rules, and package ecosystems without changing the Docker supervisor. Sandbox changes require a threat model update and maintainer security review.
