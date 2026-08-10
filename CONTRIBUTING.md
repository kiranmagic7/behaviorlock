# Contributing

BehaviorLock welcomes focused contributions that improve reproducibility, containment, evidence quality, or contributor experience.

## Start with an issue

Open an issue before changing the profile schema, CLI contract, Docker runner, sandbox flags, normalization rules, policy levels, or release process. Small documentation and test corrections can go directly to a pull request.

Security vulnerabilities belong in a private report through [GitHub Security Advisories](https://github.com/kiranmagic7/behaviorlock/security/advisories/new), not a public issue.

## Development setup

Requirements:

1. Go 1.23 or newer
2. Git
3. Docker only for runner and isolation tests
4. ShellCheck for shell changes
5. `jq` for JSON fixture checks

The first `make check` run downloads the pinned Actionlint Go module.

Run the local gate:

```bash
make check
make build
```

Build the experimental runner separately:

```bash
make runner
bin/behaviorlock doctor
```

Do not run unknown packages on a personal workstation. Use a disposable virtual machine or an ephemeral GitHub hosted runner.

## Pull request contract

A pull request should contain one coherent change and explain:

1. The problem and linked issue
2. Security and behavior impact
3. Compatibility impact on the CLI and schemas
4. Tests and documentation added
5. Any remaining uncertainty

Fixtures must contain no secrets, personal data, production logs, or live malware. Use deterministic local programs that simulate the behavior under test.

Profiles and reports may retain sensitive paths and package controlled strings. Sanitize and review every artifact before attaching it to a public issue or pull request.

If AI tools assisted the contribution, disclose that in the pull request. The contributor must review, understand, and be able to explain every submitted line. Generated code has the same provenance, license, security, and quality obligations as handwritten code.

## DCO signoff

BehaviorLock uses Developer Certificate of Origin 1.1 instead of a contributor license agreement. Sign every commit:

```bash
git commit --signoff -m "feat: describe the change"
```

The signoff certifies that you have the right to submit the work under Apache License 2.0. Read [DCO](DCO) before contributing.

Human commits require signoff. GitHub authenticated Dependabot pull requests are the only automated exception; author names or email addresses alone never qualify for an exemption.

Pull request commits use strict matching between the commit author and the `Signed-off-by` trailer. On protected `main`, GitHub may create a squash commit under the authenticated account login while preserving a GitHub noreply signoff from the reviewed commit. The push checker accepts that case only when GitHub is the recorded committer and the signoff email belongs to the same GitHub login.

If GitHub omits the trailer from its generated squash commit, the push checker fails closed unless GitHub identifies exactly one merged pull request for that commit, the pull request base is the squash parent, the retained pull request head has the same tree as the squash, and every source commit passes strict DCO verification. The checker reads only GitHub pull request metadata and the retained pull request ref. This limited path is unavailable to pull request commits.

## Review

All changes enter through a pull request. `main` requires the aggregate CI check, resolved conversations, and maintainer approval. Changes to the runner, GitHub workflows, security policy, governance, schemas, or release process require code owner review.

Maintainers may ask for a smaller change, additional evidence, or an adversarial fixture. A technically interesting change can still be declined if it expands the trust boundary faster than the project can verify it.
