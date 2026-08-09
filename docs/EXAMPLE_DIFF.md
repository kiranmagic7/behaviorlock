# Example: an install behavior diff

This example uses BehaviorLock's inert trace fixtures. It does not use Docker, make a network request, or run a live package. The fixtures reconstruct a simple update in which version 1.1.0 does everything version 1.0.0 did, plus three new actions during install.

Build the CLI, create one profile for each fixture, and compare them:

```bash
go build -trimpath -o bin/behaviorlock ./cmd/behaviorlock

bin/behaviorlock profile \
  --package example@1.0.0 \
  --trace testdata/traces/baseline.strace \
  --output baseline.profile.json

bin/behaviorlock profile \
  --package example@1.1.0 \
  --trace testdata/traces/candidate.strace \
  --output candidate.profile.json

bin/behaviorlock compare \
  --allow-external \
  --baseline baseline.profile.json \
  --candidate candidate.profile.json \
  --format markdown
```

The compare command exits with code `1` because the added behavior reaches the default review threshold. That exit code is an expected result, not a tool failure.

## Exact output

```text
# BehaviorLock observed install lifecycle diff

Package: <code>example</code>

Compared <code>1.0.0</code> with <code>1.1.0</code>. Verdict: **fail**. Highest review level: **critical**.

| Level | Rule | Behavior | Target | Reason |
| --- | --- | --- | --- | --- |
| critical | <code>BL100</code> | <code>filesystem.read</code> | <code>$HOME/.ssh/id_rsa</code> | new access to a common credential or secret path |
| high | <code>BL200</code> | <code>network.connect</code> | <code>AF_INET:198.51.100.1:443</code> | new network connection attempt during an offline lifecycle run |
| high | <code>BL300</code> | <code>process.exec</code> | <code>/bin/sh</code> | new shell, downloader, or remote access process |

## Limitations

* BehaviorLock compares observed install lifecycle behavior, not total package behavior.
* A new behavior is a review signal and is not a malware classification.
* Profiles are unsigned inputs. Structural validation does not establish authenticity or provenance.
* The caller explicitly allowed external unverified traces; sandbox and capture provenance are not attested.

This report compares behavior exercised during the selected npm install lifecycle. It does not classify malware or prove that either package version is safe.
```

## What the report means

The candidate fixture added an SSH key path read, a network connection attempt, and a shell launch. BehaviorLock reports those changes for review. It does not know why they happened, and it does not label the package. A maintainer would compare the observations with the package's documented install behavior before deciding whether the update is expected.
