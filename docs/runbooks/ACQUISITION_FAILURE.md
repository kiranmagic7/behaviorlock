# Acquisition proxy failure

## Owner

The capture operator; proxy code changes require a security reviewer.

## Trigger

Use when preparation cannot resolve or download an exact public npm version through the registry-only Unix-socket proxy, or when acquisition provenance is incomplete.

## Evidence to preserve

Preserve the package coordinate, source commit, runner and proxy image IDs, bounded stderr, proxy decision records, Docker state, and cleanup transcript. Do not preserve registry credentials because none should exist.

## Procedure

1. Stop before lifecycle or import execution. A preparation failure is not a partial successful capture.
2. Confirm the input is an exact semantic version and the allowed authority is exactly `registry.npmjs.org:443`.
3. Run `behaviorlock doctor` and inspect whether Docker, DNS at the trusted proxy boundary, or the public registry is unavailable.
4. Confirm preparation still uses network mode `none` and reaches only the private Unix relay. Never switch preparation to bridged or host networking as a workaround.
5. If the proxy denies a request, treat the denial as a policy result. Investigate lockfile or registry metadata separately; do not broaden the allowlist during the incident.
6. Retry only in a fresh disposable environment after the external failure is understood.

## Rollback

Revert to the last reviewed proxy and runner content IDs. Remove any experimental allowlist change. If a package needs a non-registry source, mark it unsupported.

## Shutdown condition

Stop when acquisition provenance cannot be completed, a redirect or authority falls outside policy, DNS resolves to a special-use address, or cleanup cannot remove the proxy network, socket volume, and containers.
