# Example: an inert behavior diff

This example uses BehaviorLock's hand-written trace fixtures. It does not use Docker, make a network request, download a package, or execute package code. It reconstructs a candidate version that adds an SSH-key-path read and an outbound connection attempt.

Run the complete bounded demonstration from the repository root:

```bash
./scripts/demo-inert.sh
```

The script builds the CLI in a temporary directory, creates and verifies both profiles and their raw-evidence companions, compares them, prints the report, and removes every temporary artifact. The comparison reaches the default review threshold, which is expected evidence rather than a tool failure.

## Report produced by the fixtures

```text
# BehaviorLock observed external phase diff

Package: <code>demo-safe</code>

Compared <code>1.0.0</code> with <code>1.1.0</code>. Review required: **true**. Highest review level: **critical**.

| Level | Rule | Behavior | Target | Evidence | Technique context | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| critical | <code>BL100</code> | <code>filesystem.read</code> | <code>$HOME/.ssh/id_rsa</code> | <code>sha256:98be88a01272:L3</code> | consistent with MITRE ATT&CK T1552.004 | new access to a common credential or secret path |
| high | <code>BL200</code> | <code>network.connect</code> | <code>AF_INET:198.51.100.1:443</code> | <code>sha256:98be88a01272:L4</code> |  | new network connection attempt during the selected observation phase |

## Added observed sequences

* One candidate-only sequence links the ordered process, credential-read, and network observations by stable event identifiers.

## Limitations

* BehaviorLock compares behavior observed during the external phase, not total package behavior.
* A new behavior is a review signal and is not a malware classification.
* Profiles and evidence companions are unsigned. Integrity verification does not establish producer authenticity or provenance.
* The caller explicitly allowed external unverified traces; sandbox and capture provenance are not attested.
```

## What the report means

The candidate fixture added two observations. `BL100` routes the credential-path read to critical review, and `BL200` routes the connection attempt to high review. The report preserves exact evidence references and ordering context, but it does not infer motive, classify malware, or prove that either version is safe. A maintainer must compare the observations with the package's documented purpose and trusted source changes.

The companion [benchmark report](../benchmark/REPORT.md) expands the inert corpus to four behavior families and keeps historical incident mappings explicitly projection-only.
