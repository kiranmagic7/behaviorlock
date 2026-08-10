#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/release-gate.sh EVIDENCE.json" >&2
  exit 2
fi

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"

exec go run ./cmd/release-gate \
  --config config/release-proofs.json \
  --evidence "$1" \
  --repository "$GITHUB_REPOSITORY" \
  --source-sha "$GITHUB_SHA"
