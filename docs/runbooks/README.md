# Operator runbooks

These runbooks apply to experimental source builds. They do not authorize analysis of malware, unknown preserved packages, third-party systems, or production hosts.

Every runbook names an owner, trigger, evidence to preserve, procedure, rollback, and shutdown condition. The operator owns the disposable host or virtual machine and must be able to destroy it without affecting trusted work.

Use the narrowest relevant runbook:

- [Disposable capture](DISPOSABLE_CAPTURE.md)
- [Evidence handling](EVIDENCE_HANDLING.md)
- [Acquisition proxy failure](ACQUISITION_FAILURE.md)
- [Tracer failure](TRACER_FAILURE.md)
- [Resource exhaustion](RESOURCE_EXHAUSTION.md)
- [Profile verification](PROFILE_VERIFICATION.md)
- [Rollback](ROLLBACK.md)
- [Cleanup](CLEANUP.md)

Stop immediately if the host is not disposable, Docker contains trusted workloads, credentials are present, the package is not an exact public-registry version, or the requested work exceeds authorization.
