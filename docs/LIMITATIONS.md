# Limitations

BehaviorLock observes one narrow execution path. The following limits are part of every result.

1. Only npm `preinstall`, `install`, and `postinstall` behavior exercised through the selected rebuild command is in scope.
2. The parser covers selected path based file calls, `execve` and `execveat`, and `connect`. It does not yet model UDP sends, socket creation, bind or listen, clone without exec, descriptor only mutation, `truncate`, or every Linux syscall.
3. Transitive dependency behavior may appear in a trace and cannot always be attributed to the target package.
4. `strace` cannot observe ordinary in process environment variable reads.
5. File contents are never captured, so a successful read reveals a path but not how data was used.
6. Offline execution blocks communication and can change package behavior.
7. Package code can detect Docker, tracing, architecture, hostname, missing secrets, and timing changes.
8. Delayed, probabilistic, targeted, runtime only, or user triggered behavior may not execute.
9. Node, npm, the dynamic linker, and native build tools generate ordinary noise.
10. Failed access attempts remain observations and may create false positives.
11. A comparable profile depends on the same runner image, architecture, Node version, npm version, and harness. The generated dependency lock digest records, but does not eliminate, dependency graph variation.
12. The Debian base image is pinned, but live operating system packages installed during a runner build are not snapshot pinned. Use the exact runner image ID for comparison.
13. The acquisition phase has a wall clock limit and memory controls but no portable Docker overlay disk quota. Preparation has no direct network route and its proxy allows only the public npm registry authority, but registry data and the shared Docker host kernel remain trusted boundaries. Use a disposable runner without valuable credentials or workloads.
14. Raw traces are retained by default in separate mode `0600` companion files and bound to normalized records by artifact and line digests. Retention improves reviewability but does not prove that the observed execution was complete or authentic.
15. An incomplete trace is an error, but a complete trace still cannot prove full coverage or prevent evasive dormant behavior.
16. Profiles and raw companions can retain sensitive paths, visible process arguments, and package controlled strings. Review every artifact before sharing it.
17. Profiles and evidence companions are unsigned. Validation checks structure, whole-artifact integrity, and exact line references, not producer authenticity. Enforcement workflows must generate profiles in a trusted job rather than accepting contributor supplied artifacts.
18. The Go CLI is tested on Linux and macOS, but full capture is verified only on GitHub hosted Linux. Native Windows and macOS tracing are not implemented.

BehaviorLock reports observations and changes. It does not report that a package is safe, clean, benign, malicious, or free of vulnerabilities.
