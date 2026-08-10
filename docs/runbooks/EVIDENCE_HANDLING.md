# Evidence handling

## Owner

The incident or review owner named before capture begins.

## Trigger

Use whenever a profile, raw evidence companion, benchmark report, terminal transcript, or trusted-profile bundle is created or received.

## Evidence to preserve

Preserve original bytes, SHA-256 digests, source commit, package coordinates, capture phase, runner identity, acquisition policy, timestamps, access decisions, and every redaction as a derived copy. Never edit the original.

## Procedure

1. Restrict raw evidence and profiles to the minimum authorized reviewers. Raw `strace` can contain paths and process arguments.
2. Verify each profile against its default evidence companion with `behaviorlock validate --profile FILE` before interpretation or transfer.
3. Record the profile stable digest and evidence artifact digest shown in the profile.
4. Store originals in an access-controlled case directory. Create redacted derivatives under different names and retain a redaction log.
5. Remove tokens, personal paths, identifiers, or package-controlled terminal content from public derivatives. Do not claim that redaction preserves every forensic property.
6. Cite observations by profile digest, behavior ID, evidence artifact digest, and exact line digest. State that signer authenticity is unverified unless a trusted bundle attestation was independently verified.

## Rollback

If an unauthorized copy was made, stop distribution, revoke access, document recipients, and follow the organization’s data-incident process. Do not silently replace or rewrite evidence.

## Shutdown condition

Close handling only when originals, derivatives, permissions, retention, and deletion dates are documented. If provenance or authorization cannot be established, quarantine the material and do not publish it.
