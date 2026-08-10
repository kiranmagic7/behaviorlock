#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/collect-release-proofs.sh OUTPUT.json" >&2
  exit 2
fi

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"

case "$GITHUB_REPOSITORY" in
  */*) ;;
  *) echo "invalid GITHUB_REPOSITORY" >&2; exit 2 ;;
esac
case "$GITHUB_SHA" in
  *[!0-9a-f]*|'') echo "invalid GITHUB_SHA" >&2; exit 2 ;;
esac
if [ "${#GITHUB_SHA}" -ne 40 ]; then
  echo "invalid GITHUB_SHA length" >&2
  exit 2
fi

output="$1"
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

gh api \
  -H "Accept: application/vnd.github+json" \
  "repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA/check-runs?per_page=100" > "$temporary"

jq -n \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg source_sha "$GITHUB_SHA" \
  --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --slurpfile config config/release-proofs.json \
  --slurpfile checks "$temporary" '
    {
      schemaVersion: 1,
      repository: $repository,
      sourceSha: $source_sha,
      generatedAt: $generated_at,
      proofs: [
        $config[0].proofs[] as $required |
        ([
          $checks[0].check_runs[] |
          select(.name == $required.check and .head_sha == $source_sha)
        ] | sort_by(.completed_at) | last) as $observed |
        if $observed == null then
          {
            id: $required.id,
            check: $required.check,
            status: "missing",
            conclusion: "missing",
            sourceSha: $source_sha,
            completedAt: "0001-01-01T00:00:00Z",
            detailsUrl: ""
          }
        else
          {
            id: $required.id,
            check: $required.check,
            status: $observed.status,
            conclusion: ($observed.conclusion // ""),
            sourceSha: $observed.head_sha,
            completedAt: ($observed.completed_at // "0001-01-01T00:00:00Z"),
            detailsUrl: $observed.details_url
          }
        end
      ]
    }
  ' > "$output"
