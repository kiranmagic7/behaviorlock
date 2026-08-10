# Provenance and release controls

BehaviorLock has build and attestation machinery, but it still has no tagged release. Adding a workflow is not the same as approving a release. The repository keeps publication disabled until the maintainer deliberately enables the protected environment and every release proof passes on the exact `main` commit.

## Version identity

Development builds report `0.1.0-dev`. Release builds inject the selected semantic version through Go linker flags. If no injected value exists, the CLI uses the Go module build version when one is available and safe to print. Control characters, surrounding whitespace, and oversized values are rejected before a version reaches terminal output or an artifact profile.

## Runner identity

`capture` and `doctor` accept `--runner`. The value must be an explicit non-`latest` tag, a local SHA-256 content ID, or an `@sha256` digest reference. BehaviorLock validates the value before it contacts Docker, resolves it once to an immutable content ID, records both the requested reference and resolved ID, then uses only that ID for metadata and acquisition execution.

Profiles are comparable only when both the requested runner reference and the resolved content ID match. This makes an operator's runner choice visible instead of treating two differently named supply paths as interchangeable by accident.

## Trusted profile bundles

The manual `Trusted profile attestation` workflow is the only workflow allowed to create a profile intended for later policy use. It runs only from protected `main`, only for a reviewed pair in `config/trusted-capture-pairs.json`, only on a GitHub-hosted runner, and only when the protected environment and `BEHAVIORLOCK_TRUSTED_PROFILE_ENABLED` repository variable authorize it.

The workflow creates both profiles in one job, retains their mode `0600` raw evidence, recomputes the report, records the source commit, workflow, run, runner image ID, and acquisition policy, then packs those files into one deterministic archive. GitHub attests the exact archive digest.

The verifier checks the archive's exact file set before extraction, all internal checksums, both profile/evidence pairs, the recomputed report, the allowlisted package pair, runner and acquisition fingerprints, source repository, source ref, source commit, signer workflow, and GitHub-hosted runner claim. Contributor-supplied profiles or bundles are not trusted simply because they pass structural validation.

The dependency-review artifact is deliberately separate from a trusted profile bundle. Its unprivileged producer has no write token, and the privileged comment workflow revalidates its contents as hostile data. That is sufficient for a bounded review comment, not for policy enforcement, a release proof, or provenance attestation. Pull-request review artifacts never satisfy gate 14.

Example verification inside a protected workflow:

```bash
export EXPECTED_REPOSITORY=kiranmagic7/behaviorlock
export EXPECTED_SOURCE_SHA="$(git rev-parse HEAD)"
export EXPECTED_SOURCE_REF=refs/heads/main
export BEHAVIORLOCK_BIN="$PWD/bin/behaviorlock"

scripts/verify-trusted-profile.sh trusted-profile.tar.gz
```

`gh attestation verify` still needs authenticated read access to the repository attestation API.

## Release proof gate

`config/release-proofs.json` maps each of the 14 roadmap gates to a unique GitHub check name. The authorized release workflow queries check runs for the exact protected commit. `scripts/release-gate.sh` rejects a proof set when any check is missing, duplicated, skipped, unsuccessful, stale, attached to another commit, or linked outside the expected GitHub Actions repository path.

The proof manifest is collected by the protected workflow from GitHub's API. A JSON file supplied by a pull request is never accepted as release authority.

## Build outputs

The no-publish dry run builds Linux and macOS archives for AMD64 and ARM64. Each archive contains the CLI, license, notice, README, and security policy. GoReleaser produces SHA-256 checksums, and pinned Syft produces an SPDX JSON SBOM for every archive. The dry run also builds the pinned runner image locally, records its content ID, and produces a separate runner-image SBOM. It uploads temporary CI artifacts but creates no tag, release, package, container image, or Marketplace listing.

The authorized release workflow is manual and disabled by default. Even after it is enabled, a protected environment approval, exact confirmation phrase, unused semantic tag, and all 14 proofs are required. It builds before publishing, signs the checksum file with keyless Sigstore, creates GitHub provenance attestations, signs the runner image by registry digest, and creates a draft GitHub release. It never runs for a pull request, push, or tag event.

## What provenance proves

Successful verification binds an artifact to a repository, workflow, commit, and hosted build identity. It does not prove that a package is safe, that observation coverage is complete, or that a maintainer's interpretation is correct. Provenance protects the evidence path. Human review still owns the decision.
