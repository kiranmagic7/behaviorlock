# Tracer failure

## Owner

The capture operator; parser or runner changes require a security reviewer.

## Trigger

Use when the trace footer or sentinel is missing, `strace` reports diagnostics, the tracer dies, parsing fails, or the profile result is `trace_incomplete`.

## Evidence to preserve

Preserve the incomplete profile if emitted, bounded tracer diagnostics, container state, exit classification, source commit, runner content ID, command transcript, and cleanup result. Do not describe incomplete evidence as a completed capture.

## Procedure

1. Stop interpretation and comparison. Complete profiles may not be synthesized from an incomplete trace.
2. Confirm the result is classified as `trace_incomplete`, not ordinary package failure.
3. Check the runner image identity, host kernel support, Docker security options, PID limits, trace tmpfs capacity, and wall-clock timeout.
4. Reproduce only with the inert tracer-failure fixtures first. Do not use an unknown package to debug the tracer.
5. If the inert fixture fails, isolate the runner or parser regression and require hosted verification before retrying package capture.

## Rollback

Return to the last reviewed runner digest and source commit. Never add host PID namespaces, broad capabilities, privileged mode, or writable trace storage to force completion.

## Shutdown condition

Stop when the tracer cannot prove both sentinels, an empty diagnostic channel, a trusted footer, and complete parse state. Preserve the failure classification and destroy the disposable environment.
