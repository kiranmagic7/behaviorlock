# User guide

## What BehaviorLock does

BehaviorLock compares what two versions of an npm package were observed doing while their install scripts ran in the same Linux harness.

Think of it as a change detector. It does not ask whether opening a file or starting a process is good or bad. It shows what appeared in the newer version but not in the older one, then assigns a review level so the most sensitive changes are easier to find.

## What question it answers

BehaviorLock can help answer:

> What did this package version begin doing during installation that the previous version did not do?

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

## What the report contains

A report lists behavior that was added or removed between two profiles.

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

## What verdicts mean

`pass` means no added observation reached the configured threshold.

`review` means behavior changed, but the highest change remained below the failure level.

`fail` means at least one added observation reached a high or critical review level.

None of these verdicts proves that a package is benign or malicious.

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

Real capture does execute package lifecycle code. Use an ephemeral GitHub hosted Linux runner or a disposable virtual machine with no valuable files, credentials, private network access, or cloud privileges.

Do not run an unknown package on a personal workstation. Docker reduces exposure, but containers share a kernel and are not a complete hostile code boundary.

## Privacy

BehaviorLock does not capture file contents. It can still record sensitive paths, process arguments, package controlled strings, hostnames visible inside the container, and network destinations.

Review profiles and reports before sharing them. Remove private paths, repository names, internal addresses, and any other information that should not be public.

## Operating systems

The current capture result describes Linux behavior.

The CLI builds on Linux and macOS. Docker Desktop may let macOS or Windows operate a Linux container, but the resulting profile is still a Linux profile. Native Windows and native macOS tracing are not implemented.

## Current maturity

There is no tagged release. Installation requires building from source, and capture requires a locally built runner image. Profiles are unsigned, so policy jobs must generate their own profiles in a trusted workflow.

This is useful for experiments and design partnerships. It is not yet a finished security product.

## Where to go next

1. Use the [README](../README.md) for commands.
2. Read [platform support](PLATFORM_SUPPORT.md) before planning cross platform use.
3. Read the [technical reference](TECHNICAL_REFERENCE.md) to understand profile compatibility.
4. Read the [threat model](THREAT_MODEL.md) before running real capture.
5. Use [GitHub Discussions](https://github.com/kiranmagic7/behaviorlock/discussions) for questions and design conversation.
