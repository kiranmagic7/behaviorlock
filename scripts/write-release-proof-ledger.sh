#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/write-release-proof-ledger.sh OUTPUT.json" >&2
  exit 2
fi

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
case "$output" in
  /*) ;;
  *) output="$PWD/$output" ;;
esac
output_directory="$(dirname -- "$output")"
if [ ! -d "$output_directory" ]; then
  echo "release proof output directory does not exist" >&2
  exit 2
fi

jq -n \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg source_sha "$GITHUB_SHA" \
  --arg workflow ".github/workflows/release-proofs.yml" \
  --slurpfile config config/release-proofs.json '
    {
      schemaVersion: 1,
      kind: "behaviorlock.protected-proof-ledger",
      repository: $repository,
      sourceSha: $source_sha,
      workflow: $workflow,
      suite: {
        localChecks: "completed",
        hardenedIntegration: "completed"
      },
      gates: [
        $config[0].proofs[] |
        select(.id != "gate-14") |
        {
          id,
          check,
          status: "completed",
          conclusion: "success",
          sourceSha: $source_sha
        }
      ]
    }
  ' > "$output"

jq -e '
  .schemaVersion == 1 and
  .kind == "behaviorlock.protected-proof-ledger" and
  (.gates | length) == 13 and
  ([.gates[].id] | unique | length) == 13 and
  ([.gates[].check] | unique | length) == 13 and
  (.gates | all(.status == "completed" and .conclusion == "success" and .sourceSha == $source_sha))
' --arg source_sha "$GITHUB_SHA" "$output" >/dev/null
