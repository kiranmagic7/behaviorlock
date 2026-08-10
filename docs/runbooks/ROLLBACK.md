# Rollback

## Owner

The maintainer responsible for the affected branch, workflow, or runner digest.

## Trigger

Use after a regression in capture integrity, containment, provenance, report meaning, automation permissions, or operator usability.

## Evidence to preserve

Preserve the failing commit, last known reviewed commit, diff, hosted check URLs, profiles and evidence involved, reproduction transcript, affected users, and rollback decision.

## Procedure

1. Disable the affected optional workflow or feature flag without deleting evidence.
2. Identify the last reviewed commit and immutable runner content ID that passed the same gate set.
3. Create a normal revert change for review. Do not rewrite protected history or force-push shared branches.
4. Rebuild from source and rerun local checks, hosted integration, benchmark expectations, cleanup, and provenance checks.
5. Mark profiles from incompatible schemas, phases, observation policies, or runner identities as non-comparable.
6. Document what was rolled back, what remains valid, and the conditions for re-enabling the feature.

## Rollback

If the rollback itself fails, disable capture and automation entirely while keeping parser-only inspection available for authorized local evidence.

## Shutdown condition

Close only when the protected branch is restored through reviewed history, hosted checks are green, affected artifacts are quarantined, and users have a clear compatibility statement.
