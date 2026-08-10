# Canary, import, and sinkhole observations

Offline lifecycle capture remains BehaviorLock's default. Import observation and the inert sinkhole are opt-in experimental modes. They produce separate profiles and do not broaden the claim that a profile records selected behavior from one bounded execution.

## Decoy canaries

Every Docker capture generates a different nonsecret value for each decoy file and environment location. Values use the reserved `behaviorlock-canary.invalid/` marker and are never copied from the host. The profile records stable canary identifiers, kinds, and locations, but not the generated values.

BehaviorLock looks for an exact generated value only where the tracer already exposes data: filesystem targets and process arguments. A match is replaced by a stable `$CANARY[...]` token before it enters a normalized behavior. The raw evidence companion remains unchanged. The sinkhole scans at most 8 KiB of each bounded request for exact generated values and retains only matching identifiers; request bytes, headers, hostnames, and bodies are discarded.

## Observed sequences

Profiles may contain deterministic `process-lineage-observed-order` sequences. A sequence is an ordered list of stable behavior identifiers from one observed root process lineage. Runtime PIDs and descriptors help construct the grouping but never enter the sequence or its identifier.

Sequences are emitted only when a selected anchor such as a sensitive read, visible canary, or file creation is followed in the same lineage by an observed process, permission, or network action. They describe ordering. They are not attack-chain names, intent claims, risk scores, or malware classifications.

## Import phase

`--phase import` resolves the installed package's public entry point after the normal exact-registry acquisition. CommonJS and ESM entry points are loaded inside the same read-only, bounded, unprivileged execution container used for lifecycle observation. Native addons and unresolved entry points produce an explicit `unsupported` profile instead of being guessed or silently treated as lifecycle evidence.

The profile records `phase: import`, the normalized entry point, CommonJS or ESM module kind, resolver version, and support outcome. Lifecycle and import profiles have different coverage scopes and comparison rejects them before diffing.

Importing a package can trigger behavior that installation does not. It can also miss behavior that needs application inputs, delayed execution, another platform, or a different export. A thrown import is recorded as a command failure; timeout, OOM, tracer failure, and output truncation retain their existing distinct incomplete outcomes.

## Inert sinkhole

`--sinkhole` first uses a trusted, no-network, zero-capability initializer to write two fixed lines into a private Docker resolver volume. The trace mounts only that single file read-only and verifies its exact content before package code runs; no host path is mounted. The responder itself starts directly as uid `65532` with zero effective capabilities and Docker network mode `none`. A namespaced `net.ipv4.ip_unprivileged_port_start=0` setting lets it bind the fixed loopback DNS, HTTP, and TCP ports without retaining `NET_BIND_SERVICE`. The trace joins only that responder's network namespace, so both containers share loopback but have no external, bridge, host-gateway, private-network, or metadata route.

The responder provides bounded synthetic services on loopback:

- UDP DNS returns only `127.0.0.1` or `::1` for valid single-question A and AAAA requests.
- HTTP returns a fixed inert stage marker.
- Raw TCP returns a fixed inert marker and closes.

The profile records `sinkhole-loopback-v1`, responder version `inert-sinkhole-v1`, bounded request counts, and any matched canary identifiers. Request counts are evidence noise and do not affect the stable semantic digest. Network mode, responder version, and canary movement do affect comparability and semantic identity.

The sinkhole does not emulate the internet, TLS services, command-and-control protocols, real credentials, or malicious payloads. It is not a claim that a package would behave the same way against a real service. Unknown hostile packages still belong on a dedicated disposable machine.

## Optional ATT&CK context

Some review rules carry optional MITRE ATT&CK identifiers with the literal relationship `consistent with`. The metadata is navigational context only. It never changes the observed behavior, review level, threshold, or product language into a technique classification.
