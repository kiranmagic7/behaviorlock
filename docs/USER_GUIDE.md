# User guide

## What BehaviorLock does

BehaviorLock compares what two versions of an npm package were observed doing during the same bounded Linux phase. Install lifecycle observation is the default; resolved entry-point import is an explicit experiment.

Think of it as a change detector. It does not ask whether opening a file or starting a process is good or bad. It shows what appeared in the newer version but not in the older one, then assigns a review level so the most sensitive changes are easier to find.

## What question it answers

BehaviorLock can help answer:

> What did this package version begin doing during the selected observation phase that the previous version did not do?

It cannot answer:

> Is this package safe?

No single execution can answer that. Code can stay dormant, detect the test environment, run only for certain users, or wait until normal application runtime.

## Who it is for

BehaviorLock is intended for:

1. Package maintainers reviewing a release
2. Security engineers investigating dependency changes
3. CI owners who want a review signal before accepting an update
4. Researchers building better software supply chain evidence

It is not yet intended for people who need a polished desktop application, a hosted dashboard, or a one click malware verdict.

## First safe journey

Run `./scripts/demo-inert.sh` before using Docker capture. The demo builds the CLI, replays two hand-written offline traces, validates their retained evidence, renders the observed difference, and removes temporary files. It does not download or execute an npm package.

The maintained corpus in `benchmark/manifest.json` declares the phase, citations, reconstruction status, exact expected behavior types and rule IDs, and unsupported signals for every fixture. `benchmark/REPORT.md` contains executed fixture results. Its historical section is explicitly projection only: no affected package or malicious archive was executed.

## What the report contains

A report lists behavior and bounded observed-order sequences that were added or removed between two compatible profiles.

Examples include:

1. A new executable was started.
2. A new credential path was inspected.
3. A file was created outside the normal disposable work directory.
4. A network connection was attempted even though execution was offline.

Each added behavior has a level:

| Level | What it means |
| --- | --- |
| Critical | Review immediately. A common secret or credential path was accessed. |
| High | Review before accepting the update. The change includes a sensitive process, network attempt, or unexpected filesystem target. |
| Medium | Inspect the change. It may be normal build behavior, but it is new. |
| Low | Usually informational, such as a new file read. |

The level describes the observation, not the author's intent.

## What the summary means

`reviewRequired: false` means the comparison found no added normalized behavior or observed sequence.

`reviewRequired: true` means at least one added behavior or observed sequence needs human review. `highestReviewLevel` identifies the highest behavior-rule group to inspect. A sequence-only change keeps that field at `none` because ordering context is not assigned an invented level.

The `--fail-on` option controls the CLI exit code used by automation. It does not change the report or classify the package.

None of these fields or exit codes proves that a package is benign or malicious.

## A sensible review process

When a report changes:

1. Confirm that both profiles used the same runner and tool versions.
2. Read the highest level additions first.
3. Check whether the package release notes or source diff explain each addition.
4. Reproduce the capture on a disposable runner if the result is surprising.
5. Ask the package maintainer privately before making a public accusation.
6. Accept a new baseline only after a person understands the change.

BehaviorLock should support a review decision, not replace one.

## Safe use

Use the fixture based quick start for learning. It does not execute downloaded package code.

Real capture executes package lifecycle or import code. Use a dedicated disposable virtual machine with no valuable files, credentials, private network access, or cloud privileges. Hosted CI should use inert fixtures unless its provider policy, isolation, and legal scope have been explicitly reviewed. The optional sinkhole has no external route, but it still changes the observed program path and is not an internet emulator.

Do not run an unknown package on a personal workstation. Docker reduces exposure, but containers share a kernel and are not a complete hostile code boundary.

## Privacy

BehaviorLock does not intentionally capture file contents. Each Docker capture generates nonsecret canary values rather than copying credentials from the host. Normalized profiles store only stable canary identifiers, but the raw mode `0600` `strace` companion can still contain visible generated values, sensitive paths, process arguments, package controlled strings, hostnames visible inside the container, and network destinations. The sinkhole retains only request counts and matching identifiers and discards request bytes.

The profile binds each behavior to the companion artifact with a full SHA 256 digest, line number, and exact line digest. `validate` and `compare` verify those references. This proves that the supplied profile and raw evidence agree; it does not authenticate their creator. Review profiles, evidence, and reports before sharing them. Remove private paths, repository names, internal addresses, and any other information that should not be public.

## Operating systems

The current capture result describes Linux behavior.

The CLI builds on Linux and macOS. Docker Desktop may let macOS or Windows operate a Linux container, but the resulting profile is still a Linux profile. Native Windows and native macOS tracing are not implemented.

## Current maturity

There is no tagged release. Installation requires building from source, and capture requires a locally built runner image or an explicitly selected image reference. Ordinary profiles are unsigned. A disabled-by-default protected workflow can produce a GitHub-attested bundle for one reviewed fixture pair, but contributor-supplied profiles remain untrusted.

This is useful for experiments and design partnerships. It is not yet a finished security product.

## Where to go next

1. Use the [README](../README.md) for commands.
2. Read [platform support](PLATFORM_SUPPORT.md) before planning cross platform use.
3. Read the [technical reference](TECHNICAL_REFERENCE.md) to understand profile compatibility.
4. Read the [threat model](THREAT_MODEL.md) before running real capture.
5. Read [provenance and release controls](PROVENANCE_AND_RELEASES.md) before using artifacts across workflows.
6. Read [canary, import, and sinkhole observations](CANARY_IMPORT_AND_SINKHOLE.md) before enabling either experimental mode.
7. Use [operator runbooks](runbooks/README.md) for capture, evidence, failure, rollback, and cleanup procedures.
8. Use the [incident analysis template](templates/INCIDENT_ANALYSIS.md) before coordinating or publishing a real finding.
9. Use [GitHub Discussions](https://github.com/kiranmagic7/behaviorlock/discussions) for questions and design conversation.
