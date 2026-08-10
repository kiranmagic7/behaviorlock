# Origins and adjacent work

BehaviorLock was designed independently as a narrow dependency version diff for npm install lifecycle behavior.

Adjacent open source work shaped the boundary:

1. [Packj](https://github.com/ossillate-inc/packj) performs static and dynamic package analysis, including install time tracing.
2. [Goodman](https://github.com/hi-heisenbug/goodman) studies runtime dependency behavior drift with eBPF.
3. [GuardDog](https://github.com/DataDog/guarddog) scans package source and metadata for suspicious patterns.
4. [Socket CLI](https://github.com/SocketDev/socket-cli) provides supply chain analysis and install gating.
5. [bob](https://github.com/k8sstormcenter/bob) and [bobctl](https://github.com/Vad1mo/bobctl) define vendor supplied behavior profiles for OCI and Kubernetes workloads.
6. [Behaviorlock by Christian Bucher](https://github.com/christian140903-sudo/behaviorlock) compares recorded AI agent behavior across model and prompt changes.

BehaviorLock's intended contribution is narrower: environment-qualified profiles for two exact npm versions, a transparent set diff, content-derived behavior identifiers, verifiable references into separately retained raw evidence, and a CI threshold that never claims to classify malware.

No source code from these projects was copied into this repository.
