# Cleanup

## Owner

The operator who started the capture or test environment.

## Trigger

Run after every success, failure, timeout, interruption, demo, or benchmark session.

## Evidence to preserve

Preserve a bounded listing of BehaviorLock-owned containers, images, networks, volumes, temporary directories, the cleanup command result, and any resource that could not be removed.

## Procedure

1. Allow the tool’s bounded cleanup context to finish. Do not interrupt cleanup to save time.
2. Confirm no container named with the current BehaviorLock capture prefix remains.
3. Confirm no temporary analysis image, acquisition socket volume, or acquisition egress network created by the current run remains.
4. Confirm local profile evidence is either moved into the authorized case directory or securely removed according to policy.
5. Remove only resources whose exact random identifiers were recorded by the current run. Never use broad Docker prune commands on a shared host.
6. Destroy the disposable VM after approved evidence export.

## Rollback

If automatic cleanup fails, quarantine the disposable host, record exact resource IDs, and remove those explicit resources manually. Do not widen the target with globs or unresolved variables.

## Shutdown condition

The session ends only when all run-owned resources are absent or the entire disposable VM has been destroyed. A cleanup failure blocks reuse of the host.
