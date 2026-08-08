# Governance

BehaviorLock begins as a founder led open source project.

## Decision rights

`@kiranmagic7` is the initial maintainer and release owner. The maintainer decides roadmap priority, accepts changes, manages security embargoes, and protects project scope.

Contributors influence decisions through issues, design proposals, pull requests, tests, and evidence. Maintainer status is earned through sustained technical judgment, respectful review, security discipline, and dependable participation.

## Significant changes

The following changes require a public design issue before implementation:

1. Profile or diff schema changes
2. New package ecosystems
3. Sandbox or privilege changes
4. New network modes
5. New persistent services or telemetry
6. Policy severity changes
7. Release and signing changes

A design issue should state the user problem, alternatives, trust boundary, compatibility effect, test plan, rollback path, and rejected options.

## Security decisions

Maintainers may discuss vulnerabilities privately until users have a safe fix. Security embargoes do not permit hidden product claims or indefinite concealment. Advisories should credit reporters who want attribution.

## Conflicts of interest

Reviewers disclose financial, employment, personal, or competitive interests that could affect judgment. A conflicted maintainer should ask another maintainer for review when one is available.

## Releases

Only a maintainer can create a release. A release requires protected `main`, a clean changelog, passing CI, checksums, provenance, an SBOM, and the security gate appropriate to that release.

The experimental capture backend cannot receive a stable release while the red team verdict remains blocked.

## Governance changes

Governance changes use the same pull request process and CODEOWNERS review as code. The current model will be reviewed when a second trusted maintainer is ready or 90 days after the first tagged release, whichever comes first.

Before appointing a second maintainer, the project will designate an independent private conduct contact and document a recusal process.
