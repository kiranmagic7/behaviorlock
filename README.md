# BehaviorLock

BehaviorLock compares selected install lifecycle system calls observed for two exact versions of a public npm package.

It records a bounded subset of path based file calls, executable launches, and connection attempts exercised during `preinstall`, `install`, and `postinstall`. It then produces a normalized profile and a reviewable version diff for CI.

> [!WARNING]
> The Docker capture backend is experimental. It is best effort observability, not a malware sandbox. Do not run unknown hostile packages on a personal workstation. Use an ephemeral GitHub hosted runner or a disposable virtual machine. BehaviorLock does not prove that a package is safe.

## Why this exists

Dependency updates often receive a source diff and a vulnerability database lookup. Those checks can miss a simple question: did the new version begin doing something the previous version never did?

BehaviorLock answers that narrow question with inspectable, environment qualified evidence. It records the resolved dependency lock digest and runner identity. A new shell process, credential path read, selected filesystem mutation, or connection attempt can become visible before a baseline changes.

## Current scope

Version `0.1.0-dev` deliberately supports one workflow:

1. Public npm registry packages
2. Exact semantic versions
3. Linux containers
4. npm install lifecycle scripts
5. Offline script execution
6. JSON, text, and Markdown diffs

Tags, ranges, Git dependencies, local paths, private registries, Windows, macOS tracing, runtime monitoring, and malware classification are outside this release.

## Quick start

Go 1.23 or newer is enough for profile parsing and comparison.

```bash
go build -o bin/behaviorlock ./cmd/behaviorlock

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

The comparison exits with `1` when an added observation reaches the configured `--fail-on` threshold. The default threshold is `high`.

The sample traces are inert fixtures. `profile --trace` marks output as `external-unverified`, and comparison refuses those profiles unless `--allow-external` is present. External traces do not attest network isolation, sandboxing, or provenance.

All profile files are unsigned. Their provenance fields are claims, not cryptographic attestations, and can be edited. For policy enforcement, capture both versions inside the same trusted CI job and protect that workflow. Never accept a profile supplied or modified by an untrusted pull request as authoritative.

> [!CAUTION]
> Profiles and reports can contain sensitive paths and package controlled strings. Review them before uploading, attaching them to an issue, or committing them. BehaviorLock never captures file contents, but paths alone can still disclose private information.

## Experimental capture

Docker capture requires the repository runner image.

```bash
make runner
bin/behaviorlock doctor

bin/behaviorlock capture \
  --experimental \
  --package example@1.0.0 \
  --timeout 2m \
  --output example.profile.json
```

The explicit `--experimental` flag is intentional. Acquisition runs as a nonroot user in a disposable container with lifecycle scripts disabled. The resolved lockfile digest is recorded, then the filesystem is committed to a temporary image. Lifecycle execution runs offline with a read only root filesystem, no host mounts, no inherited credentials, and bounded runtime resources.

The trace supervisor and `strace` run under a different identity from package scripts. Trace files live in a root owned temporary filesystem that the package UID cannot read or modify. The container begins with only `SETUID` and `SETGID` capabilities so the supervisor can drop the traced command to uid `65532`; the package does not retain those capabilities.

The implementation rejects an empty trace, missing start or end sentinel, timeout, truncated stream, malformed completion marker, parser error, or tracer process failure. Those conditions return an incomplete result and exit code `2`. This removes known false pass paths, but it is not a complete hostile code guarantee.

## What a report means

BehaviorLock uses four observation states:

1. `success`
2. `blocked`
3. `failed`
4. `unknown`

Added behavior receives a transparent review rule. For example, `BL100` marks a new access to a common credential path and `BL200` marks a network attempt during an offline run.

These rules describe what the supplied profiles record. `pass` means only that no added observation reached the chosen comparison rule. It does not authenticate the profiles, infer intent, establish full coverage, or label a package as safe or malicious.

## Security boundary

Containers share the host kernel. Package code can detect Docker, `strace`, missing network access, timing changes, and fake credentials. It can stay dormant or behave differently elsewhere. `strace` cannot observe ordinary in process environment variable reads.

Read [the threat model](docs/THREAT_MODEL.md) and [the limitations](docs/LIMITATIONS.md) before using capture.

## Repository status

The parser and comparison core are tested locally. The capture backend remains experimental until the adversarial release gates in [the roadmap](ROADMAP.md) pass on GitHub hosted Linux runners. No tagged executable release is promised yet.

## Contributing

Outside contributions are welcome. Significant behavior, schema, sandbox, or policy changes begin with an issue. Every commit must include a DCO signoff, and pull requests must pass the protected `ci-required` check.

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and [SECURITY.md](SECURITY.md).

## Name and prior work

This repository uses the owner qualified name `kiranmagic7/behaviorlock`. It is independent of the earlier `christian140903-sudo/behaviorlock` project, which checks AI agent compatibility. The two projects have different purposes and no affiliation.

BehaviorLock also does not claim ownership of the phrase “Bill of Behavior” and does not present itself as a new standard. [ORIGINS.md](docs/ORIGINS.md) records adjacent projects and the boundaries of this implementation.

## License

Apache License 2.0. Contributions are accepted under the same license through Developer Certificate of Origin 1.1 signoff.
