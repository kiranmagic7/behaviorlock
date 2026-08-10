# Inert benchmark report

Manifest: `sha256:f8b28ae7aa79db6665208cd2334115d87f29db50668fa7afb8759eb106042d2c`

All 4 inert reconstruction cases matched their exact declared expectations.

| Case | Added behavior types | Rule IDs | Highest review level |
| --- | --- | --- | --- |
| credential-network | filesystem.read, network.connect | BL100, BL200 | critical |
| process-filesystem | filesystem.write, process.exec | BL300, BL400 | high |
| dns-fileless | network.dns, network.socket, process.fileless\_exec, process.memfd | BL202, BL205, BL303 | high |
| environment-probes | environment.timing, filesystem.read | BL600, BL601 | medium |

## Projected historical coverage

These entries were not executed and are not demonstrated detections.

- **Compromised coa npm versions:** projection only; reconstructed fixture families: process-filesystem.

## Limits

- Observed results come only from inert offline trace reconstructions.
- Projected historical coverage is citation-backed analysis, not an executed detection result.
- A matched behavior family is review evidence and is not a malware, safety, or intent classification.
