# Disposable capture

## Owner

The operator who controls the disposable Linux VM and the reviewed package pair.

## Trigger

Use this procedure only after static review identifies an exact public npm version whose install or import behavior needs observation. Do not use it for preserved malware, private packages, URLs, Git sources, local paths, or unknown archives.

## Evidence to preserve

Preserve the exact source commit, runner image content ID, package versions, profile JSON files, mode `0600` evidence companions, command transcript, and cleanup result. Treat raw evidence as potentially sensitive.

## Procedure

1. Create a fresh disposable Linux VM with no trusted workloads, credentials, cloud identity, internal-network access, or reusable Docker state.
2. Review [the threat model](../THREAT_MODEL.md), then build the runner from the reviewed source commit with `make runner`.
3. Run `bin/behaviorlock doctor --runner behaviorlock-runner:dev` and stop on any failed prerequisite.
4. Capture one exact version with an explicit timeout: `bin/behaviorlock capture --experimental --package name@1.2.3 --runner behaviorlock-runner:dev --timeout 2m --output baseline.profile.json`.
5. Validate the profile and evidence companion before a second capture: `bin/behaviorlock validate --profile baseline.profile.json`.
6. Repeat for the candidate version, then compare with explicit evidence paths and an agreed review threshold.
7. Record observations as evidence, not a package verdict. Follow [evidence handling](EVIDENCE_HANDLING.md) before copying anything off the VM.

## Rollback

Do not retry by weakening isolation, raising privileges, adding host mounts, enabling host networking, or importing credentials. Revert to the reviewed runner digest or abandon the capture.

## Shutdown condition

Stop after the required profile pair and validation transcript exist, or immediately on tracer failure, unexpected Docker state, cleanup failure, host instability, or any sign that the authorization boundary was wrong. Destroy the VM after approved evidence export.
