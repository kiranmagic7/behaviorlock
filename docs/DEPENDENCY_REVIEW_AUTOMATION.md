# Split-privilege dependency review automation

BehaviorLock includes an inactive-until-merged GitHub dependency-review path for exact npm version changes. It is review assistance, not a release control or package safety decision. The design separates hostile execution from comment authority.

## Trust split

The `BehaviorLock dependency review capture` workflow runs on `pull_request` with `contents: read`. It receives no secret, identity token, pull-request write permission, inherited credential, or self-hosted runner. It checks out only `github.event.pull_request.base.sha`. A bootstrap check skips safely when the implementation does not yet exist on that trusted base revision; this lets the implementation review itself without loading code from the pull-request head.

The trusted-base helper reads the base and head root `package.json` files through GitHub's JSON API at their exact commit SHAs. It rejects malformed JSON, duplicate keys, non-npm package-manager declarations, dependency duplication across scopes, ranges, tags, URLs, Git sources, paths, option-like input, and more than one changed dependency. A lockfile-only change, missing manifest pair, addition, or removal is recorded as an explicit skip. Head repository files are never checked out or executed.

For one supported exact version pair, the unprivileged job independently downloads both public registry versions through BehaviorLock's existing acquisition policy, captures each lifecycle in the same immutable local runner, validates the retained evidence, creates a JSON diff, and uploads a bounded three-day artifact. The artifact contains data only: the plan, profiles, evidence, diff, and a digest manifest. It contains no repository-head script or generated Markdown.

The `BehaviorLock dependency review comment` workflow runs on `workflow_run` from the default branch. Its token has `actions: read`, `contents: read`, and `pull-requests: write`; artifact download requires the read permission. It never checks out the pull request or executes artifact content. Before commenting, trusted default-branch code verifies the source repository, workflow name and path, event, successful run, run attempt, source commit, pull-request number, GitHub artifact identity and digest, exact flat file set, file hashes and sizes, independently fetched package pair, profile schemas, raw evidence references, runner fingerprint, acquisition policy, and recomputed JSON diff.

Only then does the privileged job render bounded Markdown. Package-controlled strings are control-stripped, length-limited, and Markdown-escaped. The job creates or updates one comment owned by `github-actions[bot]`, located by a fixed hidden marker. Multiple bot-owned markers fail for manual reconciliation.

## Outputs

The local composite action exposes:

1. `threshold-reached`
2. `highest-review-level`
3. `added-count`
4. `skipped`
5. `baseline-profile-path` and `baseline-evidence-path`
6. `candidate-profile-path` and `candidate-evidence-path`
7. `diff-path`

No output is named or described as a verdict. `threshold-reached` is only a deterministic comparison against the configured review level.

## Operational boundary

The workflows are repository-local and are not a Marketplace action. They become active only after maintainer review and merge to the protected default branch. The privileged `workflow_run` path cannot be fully exercised from an unmerged feature branch because GitHub loads that workflow from the default branch. Local adversarial tests and actionlint therefore accompany the implementation, while default-branch hosted proof remains a post-merge requirement.

Disable both workflow files together to roll back automation. The CLI and local capture workflow remain independently usable.
