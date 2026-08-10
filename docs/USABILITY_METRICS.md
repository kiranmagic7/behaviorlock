# Usability evidence

BehaviorLock measures whether an authorized reviewer can complete the evidence journey safely. Stars, social reach, launch traffic, and discussion-site votes are not product-quality evidence.

## Measures

1. **Setup success:** the reviewed source builds and `doctor` reports the required local capabilities.
2. **Capture completion:** the selected phase produces a complete profile and retained evidence, or a precise fail-closed state.
3. **Evidence verification:** a reviewer can validate the profile/evidence pair and identify tampering.
4. **Deterministic replay:** repeated inert replay produces the same semantic profile digest.
5. **Report comprehension:** the reviewer can identify phase, added observations, highest review level, evidence limitations, and the absence of a package verdict.
6. **False-positive feedback:** reviewers can report a noisy rule with the exact behavior ID and evidence reference without weakening raw evidence retention.
7. **Cleanup success:** every run-owned container, image, network, volume, and temporary artifact is absent at shutdown.

## Collection boundary

Metrics are operator-recorded. BehaviorLock sends no telemetry. Do not record raw evidence, secrets, personal identifiers, package-controlled output, or third-party data in a usability observation. Use the JSON schema and example in `docs/templates` for consistent local records.

Completion time is context, not a target that justifies weaker verification. A failed or skipped step remains failed or skipped; never coerce it to success for a dashboard.
