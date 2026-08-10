# Evidence model

BehaviorLock separates normalized meaning from raw observation evidence. A profile is useful only when a reviewer can move from a reported behavior back to the exact retained trace line without making the stable comparison digest depend on line numbers or capture noise.

## Artifact pair

A successful `capture` or `profile` command writes two mode `0600` files:

1. A JSON profile containing normalized behaviors and artifact metadata
2. A raw `strace` companion containing the observed lines

The default companion path is `<profile>.evidence.strace`. A caller can select a different file with `--evidence-output`. JSON written to stdout still requires a separate evidence file; raw trace bytes are never mixed into the JSON stream.

The evidence file is written before the profile. Each file is staged beside its destination, synchronized, and renamed into place. A successfully written profile therefore never points to an evidence path that the same command failed to create. A failed profile rename can leave an unreferenced evidence file, which is safe to inspect or discard.

## Artifact metadata

`capture.evidenceArtifact` records:

| Field | Contract |
| --- | --- |
| `sha256` | Digest of the complete raw companion bytes |
| `byteSize` | Exact byte count, bounded to 64 MiB |
| `mediaType` | `application/vnd.behaviorlock.strace` |
| `format` | `strace-lines-v1` |
| `retention` | `retained` or `external-unverified` |
| `envelope` | Trusted harness payload or caller-supplied external trace |

`retained` means the local trusted-harness command wrote the companion. It is not a signature. `external-unverified` means the caller supplied the trace and BehaviorLock makes no claim about how it was captured.

## Behavior references

Each normalized behavior has a stable semantic `id` derived from its behavior key. It also retains up to eight evidence references. Each reference contains the complete artifact digest, a one-based raw line number, and the SHA 256 digest of the exact bytes on that line excluding the final line-feed separator.

Equivalent repeated observations are counted and deduplicated. The first eight unique references in deterministic line order are retained. The limit prevents highly repetitive traces from inflating profiles while preserving multiple examples for review.

## Validation

`validate` and `compare` load the profile and its companion evidence. They reject the pair unless:

1. The profile is valid schema v2 with no unknown fields or trailing JSON values.
2. The companion byte size and complete digest match `evidenceArtifact`.
3. Every behavior ID matches its normalized semantic key.
4. Every referenced artifact digest matches the profile artifact.
5. Every referenced line exists and its exact digest matches.

Successful validation proves profile-to-artifact consistency. It does not authenticate the producer, prove that the trace was complete, or establish that the package is safe. Ordinary profiles continue to declare `attestation: none`. The protected trusted-profile workflow can place a specifically reviewed pair into a separate GitHub-attested bundle; verification of that bundle does not authenticate any other profile.

## Stable digest and compatibility

The stable profile digest excludes duration, evidence artifact metadata, raw line references, repeat counts, and capture-local process, parent, descriptor, and attribution context. These fields can change between equivalent captures without changing the meaning of the normalized behavior set. Observation policy, acquisition policy, allowed authority, and immutable proxy image identity remain in the digest because changing an observation or egress boundary changes the meaning of a capture.

Schema v1 remains published as a historical contract. The current CLI writes schema v2 and refuses cross-version comparison. Regenerate historical profiles with the current capture contract rather than silently discarding their missing evidence guarantees.

## Privacy

Raw traces can contain paths, visible process arguments, package-controlled strings, and network destinations. Companion files are private evidence, not automatic publication artifacts. Review and redact deliberately before sharing; redaction creates a different artifact and requires a regenerated profile.
