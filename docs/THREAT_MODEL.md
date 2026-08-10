# Threat model

## Assets

BehaviorLock protects the host filesystem, credentials, Docker daemon, local network, cloud metadata endpoints, CI runner, trace integrity, and user trust.

## Hostile inputs

The package name, package archive, lifecycle scripts, resolved import entry point, native binaries, transitive dependencies, package output, filesystem paths, syscall arguments, bounded sinkhole request bytes, and contributor supplied code are untrusted.

## Trust boundaries

The important boundaries are:

1. CLI to Docker
2. npm registry to preparation container
3. container to host kernel
4. traced package to trace collector
5. raw trace to normalized report
6. contributor pull request to GitHub Actions
7. traced package to optional inert sinkhole

## Primary threats and controls

### Command injection

Only exact registry versions are accepted. Docker is invoked with argument arrays. Package input cannot alter images, entrypoints, mounts, environment variables, container names, or Docker flags.

Capture resolves mutable local image tags to validated SHA 256 content IDs before use. Preparation and execution use those immutable IDs so a concurrent local retag cannot change the environment after profile evidence is collected.

### Credential exposure

The container environment is an allowlist. Host environment variables and user configuration are not inherited. Host home, repository, Docker socket, SSH files, npm configuration, and cloud credentials are never mounted. Uppercase and lowercase proxy variables are explicitly set to empty because Docker client configuration can otherwise inject proxy values into new containers.

Each capture generates distinct nonsecret canary values for disposable credential-file and environment locations. No value comes from the host. Profiles retain stable canary identifiers and declared locations, not generated values. A value is referenced only when it appears exactly on an already observed path, process-argument, or bounded sinkhole surface.

### Network access

Lifecycle and import execution use Docker network mode `none` by default. Connect attempts can still appear in `strace`, but they cannot reach an external destination through the container network.

The optional sinkhole's trusted supervisor starts with only `SETUID` and `SETGID` so it can configure its Docker-managed resolver file and drop identity. The responder then runs as uid `65532` with zero effective and bounding capabilities in Docker network mode `none`. A namespaced unprivileged-port setting permits its fixed loopback DNS, HTTP, and TCP listeners without granting `NET_BIND_SERVICE`. The traced container joins only the sinkhole's network namespace and verifies that it inherited the exact loopback resolver configuration, providing unrouted loopback access to those responders. It does not emulate the internet or any real service. It scans no more than 8 KiB of a request for exact generated canary values, retains only stable identifiers and counts, and discards request bytes.

The preparation container uses network mode `none`. Npm can reach only a loopback relay into a private Unix socket. The proxy sidecar accepts CONNECT only for `registry.npmjs.org:443`, rejects unsafe or mixed DNS answers, and dials a validated public IP without a second lookup. Lockfile validation rejects nonregistry dependency sources. This limits acquisition destinations but does not make registry metadata or package archives trustworthy. Hosted proof and security review remain required before the release gate closes.

### Host modification

Selected lifecycle or import execution has a read only root filesystem and no host mounts. Writable work, temporary, and home locations are bounded tmpfs mounts. The container receives no Docker socket or host namespace.

### Resource exhaustion

Docker bounds memory, process count, CPU, file descriptors, single-file size, shared memory, and runtime tmpfs size. The supervisor enforces an overall wall-clock timeout and output limits. Docker's authoritative OOM state is inspected before cleanup; exit code 137 alone is never treated as proof of OOM. Docker does not provide a portable overlay disk quota for preparation, so acquisition still belongs on a disposable runner. Cleanup targets only cryptographically random container, image, volume, and network names created for the current run and uses a bounded cleanup context.

### Trace tampering

The trace supervisor and `strace` run separately from the package uid. The supervisor retains `SYS_PTRACE` only inside the container PID namespace; the package runs as uid `65532` with zero effective capabilities. Root owned mode `0700` trace storage prevents the package from erasing or replacing raw trace files. Start and end sentinel reads, a nonempty recognized event set, an empty root owned tracer diagnostic file, a footer, and tracer exit status must all be present. A missing sentinel, tracer diagnostic, timeout, parser error, or output limit yields an incomplete result.

Package code can still detect tracing, alter its own behavior, attack the shared kernel, or exploit a tracer or runtime vulnerability. A tagged executable release remains blocked until broader adversarial tests show that package output cannot enter the trace channel and tracees terminate when the tracer dies.

### CI compromise

Pull request workflows use GitHub hosted runners, read only repository permissions, no secrets, and the `pull_request` event. `pull_request_target` and self hosted runners are prohibited for untrusted contribution code.

Profile JSON and its raw evidence companion are not signed. A contributor can forge both artifacts and their provenance fields together. The current validator proves that the pair agrees by checking the whole artifact digest and each exact line reference; it does not authenticate the producer. A policy workflow must capture both versions itself after checkout, must not trust profiles or evidence from the pull request, and must keep its workflow definition under code owner review.

## Residual risk

Containers are not virtual machines. Docker and `strace` do not contain every hostile package. Rootless Docker, user namespace remapping, Docker Desktop's virtual machine, or a disposable Linux virtual machine reduces risk. The trusted proxy can reach its egress bridge, while policy restricts untrusted acquisition requests to one registry authority. The optional sinkhole can change package behavior and is evidence of one synthetic interaction only. Unknown hostile packages should not run on a personal workstation or a network trusted host.

## Security release gate

The capture backend cannot graduate from experimental until the adversarial cases in [ROADMAP.md](../ROADMAP.md) pass and the security review returns `Pass`.
