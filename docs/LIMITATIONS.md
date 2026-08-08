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
13. The acquisition phase has a wall clock limit and memory controls but no portable Docker overlay disk quota. A disposable runner remains necessary.
14. Raw traces are hashed but not retained by default. Content derived evidence identifiers are stable references to normalized records, not a substitute for raw forensic evidence.
15. An incomplete trace is an error, but a complete trace still cannot prove full coverage or prevent evasive dormant behavior.
16. Profiles can retain sensitive paths and package controlled strings. Review artifacts before sharing them.
17. Profiles are unsigned JSON. Validation checks structure and internal consistency, not authenticity. Enforcement workflows must generate profiles in a trusted job rather than accepting contributor supplied artifacts.

BehaviorLock reports observations and changes. It does not report that a package is safe, clean, benign, malicious, or free of vulnerabilities.
