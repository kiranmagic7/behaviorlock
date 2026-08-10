# Limitations

BehaviorLock observes one narrow execution path. The following limits are part of every result.

1. The default lifecycle phase covers only npm `preinstall`, `install`, and `postinstall` behavior exercised through the selected rebuild command. The optional import phase covers only loading the resolved public entry point. The phases are separate and cannot be compared.
2. The parser covers selected path- and descriptor-based file operations; executable and child-process creation; anonymous memory files; process tracing; socket, connection, send, DNS, bind, listen, and accept activity; and selected timing calls. It still does not model every Linux syscall, protocol, payload, descriptor operation, memory mapping, or process-control path.
3. Transitive dependency behavior may appear in a trace and cannot always be attributed to the target package.
4. `strace` cannot observe ordinary in process environment variable reads. Generated canary movement is visible only if the exact nonsecret value later appears in an observed process argument, filesystem target, or bounded sinkhole request.
5. File contents are never intentionally captured by the normalized profile. A successful read reveals a path but not how data was used; retained raw trace evidence can contain visible nonsecret canary values or package-controlled arguments.
6. Offline execution blocks communication and can change package behavior. The optional sinkhole also changes behavior and provides only fixed inert loopback responses, never a real service.
7. Package code can detect Docker, tracing, architecture, hostname, synthetic canaries, missing real secrets, sinkhole behavior, and timing changes.
8. Delayed, probabilistic, targeted, runtime only, or user triggered behavior may not execute.
9. Node, npm, the dynamic linker, and native build tools generate ordinary noise.
10. Failed access attempts remain observations and may create false positives.
11. A comparable profile depends on the same phase, runner image reference and ID, architecture, Node version, npm version, `strace` version, network and sinkhole policy, sandbox, coverage scope, and observation policy. The generated dependency lock digest records, but does not eliminate, dependency graph variation.
12. The Debian base image is pinned, but live operating system packages installed during a runner build are not snapshot pinned. Use the exact runner image ID for comparison.
13. The acquisition phase has a wall clock limit and memory controls but no portable Docker overlay disk quota. Preparation has no direct network route and its proxy allows only the public npm registry authority, but registry data and the shared Docker host kernel remain trusted boundaries. Use a disposable runner without valuable credentials or workloads.
14. Raw traces are retained by default in separate mode `0600` companion files and bound to normalized records by artifact and line digests. Retention improves reviewability but does not prove that the observed execution was complete or authentic.
15. An incomplete trace is an error, but a complete trace still cannot prove full coverage or prevent evasive dormant behavior.
16. Profiles and raw companions can retain sensitive paths, visible process arguments, and package controlled strings. Review every artifact before sharing it.
17. Ordinary profiles and evidence companions are unsigned. Validation checks structure, whole-artifact integrity, and exact line references, not producer authenticity. A separately verified trusted-profile bundle can attest a reviewed pair, but it does not authenticate arbitrary local or contributor-supplied profiles.
18. The Go CLI is tested on Linux and macOS, but full capture is verified only on GitHub hosted Linux. Native Windows and macOS tracing are not implemented.
19. Descriptor attribution follows successful calls, descriptor duplication, close-on-exec state, process exit, and ordinary fork inheritance. It does not fully model every `CLONE_FILES`, namespace, race, or kernel-specific descriptor-sharing edge case, so attribution remains review context rather than proof of causation.
20. Observation sequences retain first-seen normalized behavior order within a bounded process lineage. They are ordering context, not proof of causation, intent, or an attack chain.
21. Optional MITRE ATT&CK references use the literal relationship `consistent with`. They are navigational context and never change a rule, review level, or package classification.
22. The inert benchmark proves only that the current parser and rule engine match declared hand-written trace expectations. It does not execute the cited historical packages, reproduce their consequences, or measure a real-world detection rate.
23. Historical coverage entries are projections from public sources. A cited package name or advisory does not establish that every affected version expressed the reconstructed behavior in this harness.
24. Release gate reports reflect the named GitHub checks visible for one exact commit at collection time. Checked-in snapshots become stale and never authorize publication.
25. The offline usability journey verifies comprehension and evidence mechanics without Docker. Container containment, acquisition egress, resource boundaries, and cleanup require the separate hosted Linux integration.

BehaviorLock reports observations and changes. It does not report that a package is safe, clean, benign, malicious, or free of vulnerabilities.
