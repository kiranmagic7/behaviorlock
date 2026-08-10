# Resource exhaustion

## Owner

The capture operator; limit changes require security and reliability review.

## Trigger

Use for timeout, OOM, process, descriptor, tmpfs, file-size, output, or syscall-volume exhaustion, including a `resource_exhausted` or `timed_out` result.

## Evidence to preserve

Preserve the authoritative Docker state, configured limits, result envelope, bounded diagnostics, profile if emitted, source commit, runner ID, and cleanup transcript.

## Procedure

1. Stop the capture and confirm no package process or analysis container survived the hard wall-clock deadline.
2. Distinguish authoritative Docker OOM state from signal-style exit code 137. The exit code alone is not OOM proof.
3. Identify the first exhausted boundary. Do not raise several limits at once.
4. Reproduce the boundary with the corresponding inert resource fixture.
5. If the reviewed use case legitimately needs a different bound, change one documented limit, retain a hard maximum, and rerun every resource and cleanup check on a hosted disposable runner.
6. Treat partial traces as incomplete even when they contain useful-looking events.

## Rollback

Restore the previous reviewed limits and runner digest. Remove experimental images and profiles whose capture conditions no longer match the comparison pair.

## Shutdown condition

Stop when the host becomes unstable, Docker cannot report authoritative state, cleanup leaves resources, or a higher limit would exceed the disposable host’s reviewed capacity.
