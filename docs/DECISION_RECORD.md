# Initial decision record

Date: 2026 08 08

Decision owner: project owner

Technical owner: `@kiranmagic7`

## Decision

Build and publish a founder led open source experiment for deterministic npm install lifecycle behavior comparison. Use the owner qualified repository name `kiranmagic7/behaviorlock`, while disclosing the unrelated earlier project with the same repository name.

## Mission served

Reduce supply chain update risk through inspectable evidence that ordinary maintainers can run in CI.

## Evidence

Known scanners already cover vulnerabilities, metadata, and static patterns. Install time dynamic analysis also exists. The useful remaining wedge is a small two version comparison with stable profiles, transparent rules, and explicit rejection of known incomplete evidence states.

## Tradeoffs

The narrow scope produces less dramatic claims and better testability. Offline execution improves containment and reduces coverage. Docker improves accessibility but cannot provide a hostile code isolation guarantee. Acquisition network isolation is weaker than lifecycle isolation and must remain visible as a release blocker.

## Risk and reversibility

Code, schema, and repository settings are reversible. A misleading security claim, credential leak, host escape, or confused project identity is harder to repair. Public copy must remain explicit about limitations and prior work.

## Success measures

1. Deterministic parser and diff tests pass.
2. Hostile package specifications cannot alter Docker arguments.
3. Incomplete traces never pass.
4. GitHub hosted isolation fixtures pass before any tagged executable release.
5. `main` requires pull requests, one review, code owner review, resolved conversations, and the aggregate CI check.
6. External contributors can reproduce tests without privileged infrastructure.

## Review date

Review the experiment before any `v0.1.0` tag and again 30 days after the repository becomes public.

## Kill or pivot conditions

Pause capture if containment tests expose host assets, trace tampering can produce a false pass, maintenance demand exceeds review capacity, or the naming collision creates material confusion. Preserve the parser and profile format even if capture moves to a disposable virtual machine backend.
