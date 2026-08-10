#!/bin/sh
set -eu

repository_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
temporary_directory="$(mktemp -d)"
cleanup_usability() {
  rm -rf -- "$temporary_directory"
}
trap cleanup_usability EXIT HUP INT TERM

behaviorlock_binary="$temporary_directory/behaviorlock"
release_report_binary="$temporary_directory/release-report"
baseline_profile="$temporary_directory/baseline.profile.json"
candidate_profile="$temporary_directory/candidate.profile.json"
candidate_repeat="$temporary_directory/candidate-repeat.profile.json"
comparison="$temporary_directory/comparison.json"

cd "$repository_root"
go build -trimpath -o "$behaviorlock_binary" ./cmd/behaviorlock
go build -trimpath -o "$release_report_binary" ./cmd/release-report

BEHAVIORLOCK_BIN="$behaviorlock_binary" ./scripts/demo-inert.sh > "$temporary_directory/demo.txt"
grep -q 'evidence, not a package verdict' "$temporary_directory/demo.txt"
grep -q 'Demo complete' "$temporary_directory/demo.txt"

"$behaviorlock_binary" profile \
  --package usability-check@1.0.0 \
  --trace benchmark/corpus/credential-network/baseline.strace \
  --output "$baseline_profile" >/dev/null
"$behaviorlock_binary" profile \
  --package usability-check@1.1.0 \
  --trace benchmark/corpus/credential-network/candidate.strace \
  --output "$candidate_profile" >/dev/null
"$behaviorlock_binary" profile \
  --package usability-check@1.1.0 \
  --trace benchmark/corpus/credential-network/candidate.strace \
  --output "$candidate_repeat" >/dev/null

"$behaviorlock_binary" validate --profile "$baseline_profile" > "$temporary_directory/baseline-validation.txt"
"$behaviorlock_binary" validate --profile "$candidate_profile" > "$temporary_directory/candidate-validation.txt"
grep -q 'raw evidence verified; signer authenticity not verified' "$temporary_directory/baseline-validation.txt"
grep -q 'raw evidence verified; signer authenticity not verified' "$temporary_directory/candidate-validation.txt"

if ! cmp -s "$candidate_profile" "$candidate_repeat" || ! cmp -s "$candidate_profile.evidence.strace" "$candidate_repeat.evidence.strace"; then
  echo "identical inert replay did not produce identical profile and evidence bytes" >&2
  exit 1
fi

tampered_evidence="$temporary_directory/tampered.strace"
cp "$candidate_profile.evidence.strace" "$tampered_evidence"
printf 'tampered\n' >> "$tampered_evidence"
if "$behaviorlock_binary" validate --profile "$candidate_profile" --evidence "$tampered_evidence" >/dev/null 2>&1; then
  echo "evidence validation accepted a tampered companion" >&2
  exit 1
fi

"$behaviorlock_binary" compare \
  --allow-external \
  --baseline "$baseline_profile" \
  --candidate "$candidate_profile" \
  --format json \
  --fail-on none \
  --output "$comparison"
jq -e '
  .phase == "external" and
  .summary.reviewRequired == true and
  .summary.highestReviewLevel == "critical" and
  ([.added[].ruleId] | unique | sort) == ["BL100", "BL200"] and
  (.limitations | any(contains("not a malware classification")))
' "$comparison" >/dev/null

./scripts/check-benchmark.sh > "$temporary_directory/benchmark.txt"

source_sha="$(git rev-parse HEAD)"
generated_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
jq -n \
  --arg repository "kiranmagic7/behaviorlock" \
  --arg source_sha "$source_sha" \
  --arg generated_at "$generated_at" \
  --slurpfile config config/release-proofs.json '
    {
      schemaVersion: 1,
      repository: $repository,
      sourceSha: $source_sha,
      generatedAt: $generated_at,
      proofs: [$config[0].proofs[] | {
        id, check, status: "missing", conclusion: "missing",
        sourceSha: $source_sha, completedAt: "0001-01-01T00:00:00Z", detailsUrl: ""
      }]
    }
  ' > "$temporary_directory/missing-proofs.json"
set +e
"$release_report_binary" \
  --evidence "$temporary_directory/missing-proofs.json" \
  --repository kiranmagic7/behaviorlock \
  --source-sha "$source_sha" \
  --format json > "$temporary_directory/release-report.json"
release_report_exit=$?
set -e
if [ "$release_report_exit" -ne 1 ]; then
  echo "blocked release report exited $release_report_exit instead of 1" >&2
  exit 1
fi
jq -e '.allGatesSatisfied == false and .gatesExpected == 14 and .gatesSatisfied == 0 and (.gates | all(.satisfied == false))' \
  "$temporary_directory/release-report.json" >/dev/null

echo "usability journey: build, inert replay, evidence verification, interpretation, fail-closed release report, and cleanup passed"
