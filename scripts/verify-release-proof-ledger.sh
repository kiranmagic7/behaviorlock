#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: scripts/verify-release-proof-ledger.sh LEDGER.json GATE_ID CHECK_NAME" >&2
  exit 2
fi

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"

ledger="$1"
gate_id="$2"
check_name="$3"
if [ -L "$ledger" ] || [ ! -f "$ledger" ]; then
  echo "release proof ledger must be a regular non-symlink file" >&2
  exit 1
fi
if [ "$(wc -c < "$ledger" | tr -d ' ')" -gt 1048576 ]; then
  echo "release proof ledger exceeds 1 MiB" >&2
  exit 1
fi

jq -e \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg source_sha "$GITHUB_SHA" \
  --arg gate_id "$gate_id" \
  --arg check_name "$check_name" '
    (keys | sort) == ["gates", "kind", "repository", "schemaVersion", "sourceSha", "suite", "workflow"] and
    (.suite | keys | sort) == ["hardenedIntegration", "localChecks"] and
    .schemaVersion == 1 and
    .kind == "behaviorlock.protected-proof-ledger" and
    .repository == $repository and
    .sourceSha == $source_sha and
    .workflow == ".github/workflows/release-proofs.yml" and
    .suite.localChecks == "completed" and
    .suite.hardenedIntegration == "completed" and
    (.gates | length) == 13 and
    ([.gates[].id] | unique | length) == 13 and
    ([.gates[].check] | unique | length) == 13 and
    (.gates | all((keys | sort) == ["check", "conclusion", "id", "sourceSha", "status"])) and
    ([.gates[] | select(
      .id == $gate_id and
      .check == $check_name and
      .status == "completed" and
      .conclusion == "success" and
      .sourceSha == $source_sha
    )] | length) == 1
  ' "$ledger" >/dev/null
