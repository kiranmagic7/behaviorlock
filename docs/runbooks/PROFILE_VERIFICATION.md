# Profile verification

## Owner

The reviewer consuming a profile or diff.

## Trigger

Use before comparing, sharing, citing, or making a policy decision from any profile.

## Evidence to preserve

Preserve the profile and evidence companion bytes, stable digest, evidence artifact digest, package coordinates, phase, capture result, runner and acquisition fingerprints, and any trusted-bundle attestation result.

## Procedure

1. Run `behaviorlock validate --profile profile.json`. The default companion is `profile.json.evidence.strace`; pass `--evidence` explicitly when stored elsewhere.
2. Reject unknown schema versions, unknown fields, non-normalized IDs, invalid line digests, whole-artifact mismatch, incomplete results, or unsafe provenance claims.
3. Confirm both profiles have the same phase, observation policy, runner reference and content ID, acquisition controls, trace-integrity mode, and sandbox profile.
4. For external traces, require `--allow-external` and state that sandbox and producer provenance are unverified.
5. For policy use, verify the trusted bundle’s GitHub attestation, repository, workflow, protected commit, exact file set, checksums, and reviewed package pair. Structural validation alone is not authenticity.
6. Interpret `reviewRequired` and `highestReviewLevel` as review routing, not a safety or malware verdict.

## Rollback

Withdraw any report derived from failed evidence, record the reason, restore the original bytes, and regenerate only from a verified pair.

## Shutdown condition

Stop when either profile or evidence companion is missing, modified, incompatible, incomplete, unauthenticated for its intended policy use, or attached to a different package pair.
