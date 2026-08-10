#!/bin/sh
set -eu

repository_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
temporary_directory="$(mktemp -d)"
cleanup_ledger_test() {
  rm -rf -- "$temporary_directory"
}
trap cleanup_ledger_test EXIT HUP INT TERM

cd "$repository_root"
export GITHUB_REPOSITORY=kiranmagic7/behaviorlock
export GITHUB_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

./scripts/write-release-proof-ledger.sh "$temporary_directory/ledger.json"
jq -r '.proofs[] | select(.id != "gate-14") | [.id, .check] | @tsv' config/release-proofs.json |
  while IFS="$(printf '\t')" read -r gate_id check_name; do
    ./scripts/verify-release-proof-ledger.sh "$temporary_directory/ledger.json" "$gate_id" "$check_name"
  done

jq '.gates[0].conclusion = "skipped"' "$temporary_directory/ledger.json" > "$temporary_directory/skipped.json"
if ./scripts/verify-release-proof-ledger.sh "$temporary_directory/skipped.json" gate-01 gate-01-input-validation >/dev/null 2>&1; then
  echo "proof verifier accepted a skipped gate" >&2
  exit 1
fi

jq '.gates[0].unexpected = true' "$temporary_directory/ledger.json" > "$temporary_directory/unknown.json"
if ./scripts/verify-release-proof-ledger.sh "$temporary_directory/unknown.json" gate-01 gate-01-input-validation >/dev/null 2>&1; then
  echo "proof verifier accepted an unknown field" >&2
  exit 1
fi

jq '.sourceSha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' "$temporary_directory/ledger.json" > "$temporary_directory/wrong-source.json"
if ./scripts/verify-release-proof-ledger.sh "$temporary_directory/wrong-source.json" gate-01 gate-01-input-validation >/dev/null 2>&1; then
  echo "proof verifier accepted a different source commit" >&2
  exit 1
fi

echo "release proof ledger tests passed"
