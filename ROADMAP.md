# Roadmap

## Public experiment

1. Publish parser, profile, comparison, schemas, threat model, and experimental Docker runner.
2. Keep capture behind explicit acknowledgement.
3. Accept outside fixtures, parser improvements, documentation, and containment tests.
4. Protect `main` with the aggregate CI gate and maintainer review.

## Gate for v0.1.0

Every item below must pass on a GitHub hosted Linux runner:

1. Shell metacharacters, control characters, tags, ranges, URLs, paths, aliases, and leading options are rejected before Docker starts.
2. Package input cannot change the image, entrypoint, mounts, network, environment, or Docker flags.
3. Host environment, home, npm configuration, SSH material, Git configuration, cloud credentials, and Docker socket never appear inside the container or report.
4. Root filesystem writes fail and work directory writes succeed.
5. Lifecycle TCP, UDP, DNS, private address, host gateway, and cloud metadata attempts fail.
6. Acquisition uses allowlisted public registry egress or an equivalent disposable host boundary with no sensitive routes.
7. Child, grandchild, native executable, and shell activity remain observable.
8. Tracer death and tracer diagnostics terminate tracees and produce `trace_incomplete`.
9. Fake syscall lines, terminal control characters, and GitHub workflow commands cannot enter the trace channel.
10. Process, memory, descriptor, file, output, syscall, and timeout exhaustion stop within limits and leave no container or image.
11. Unsupported tracing fails closed without privileged mode, disabled seccomp, host namespaces, or broad capabilities.
12. Ten repeated trusted fixture runs produce the same normalized behavior set and stable digest.
13. Every added report item points to retained raw trace evidence.
14. Trusted CI profiles carry verifiable provenance or an artifact attestation before they are used as cross-workflow policy inputs.

## Later options

Only after the first gate passes:

1. Rootless Docker guidance and verification
2. A disposable virtual machine capture backend
3. SARIF output
4. Policy files with explicit allow and review rules
5. OCI artifact publication for profiles
6. Additional package ecosystems

## Non goals

BehaviorLock will not become a malware label, vulnerability database, SBOM replacement, cloud dashboard, AI risk judge, or automatic baseline approval service.
