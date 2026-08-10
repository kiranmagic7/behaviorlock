# Resource boundaries and repeatability

BehaviorLock treats resource failure as evidence about the capture, not as a package verdict. The execution container has independent limits so one runaway dimension cannot silently consume the host.

## Execution boundaries

| Boundary | Default execution limit | Failure contract |
| --- | --- | --- |
| Wall clock | Caller selected, 10 seconds through 10 minutes | `timed_out` with no trusted evidence |
| Memory and swap | 512 MiB combined | `resource_exhausted` only when Docker reports `OOMKilled: true` |
| Processes | Docker pids limit 128 and `nproc` 128 | Command failure or incomplete trace, depending on whether the lifecycle can finish its sentinel sequence |
| File descriptors | 1,024 | Observed failure remains in the retained trace when the sentinel sequence completes |
| Single file size | 64 MiB | Command failure or incomplete trace; no core file is permitted |
| Work tmpfs | 384 MiB | Command failure or incomplete trace |
| Temporary tmpfs | 96 MiB | Command failure or incomplete trace |
| Home tmpfs | 8 MiB | Command failure or incomplete trace |
| Trace tmpfs | 128 MiB | `trace_incomplete`; no trusted footer is emitted when sentinel evidence is missing |
| Raw trace accepted by the CLI | 64 MiB | `trace_incomplete` with `truncated: true` when the Docker stream exceeds its bound |
| Parsed line | 256 KiB | Parser error and incomplete capture |
| Recognized observations | 250,000 | Parser error and incomplete capture |

Exit code 137 is not classified as an out-of-memory event by itself. A signal-style exit without Docker's authoritative OOM state remains `trace_incomplete`. Cancellation, tracer death, missing sentinels, output truncation, and ordinary lifecycle failure also remain distinct states.

Cleanup uses only cryptographically random names created for the current run. A bounded background cleanup context removes the preparation, proxy, and trace containers; temporary committed image; private socket volume; and acquisition network after success or failure.

## Inert boundary fixtures

Hosted integration uses only local inert fixtures. It exercises process, memory, descriptor, work-tmpfs, file-size, package-output, syscall-volume, timeout, signal, and real-tracer-death paths. Each case has its own hard wall clock and verifies that no tracee or capture resource remains. No preserved or live malware is used.

## Repeatability contract

The trusted inert fixture is captured ten times. Every run must produce the same normalized behavior-ID set and stable profile digest. The check intentionally excludes duration, runtime process and descriptor identifiers, evidence coordinates, raw line order, and repeat counts from semantic equality.

Raw trace digests and count digests are still recorded for each run. Variance in those fields is reported as a count of distinct values; it is never used to suppress credential access, networking, process execution, environment probes, or writes outside disposable roots. Any semantic-set or stable-digest disagreement fails the gate and prints the per-run report for investigation.
