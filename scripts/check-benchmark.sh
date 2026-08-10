#!/bin/sh
set -eu

repository_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
temporary_directory="$(mktemp -d)"
cleanup_benchmark() {
  rm -rf -- "$temporary_directory"
}
trap cleanup_benchmark EXIT HUP INT TERM

cd "$repository_root"
go run ./cmd/benchmark-report --manifest benchmark/manifest.json --format json > "$temporary_directory/report.json"
jq -e '
  .kind == "behaviorlock.inert-benchmark.report" and
  .observed.expectationsMatched == true and
  .observed.casesEvaluated == .observed.casesMatched and
  (.projectedHistoricalCoverage | all(.status == "projection-only"))
' "$temporary_directory/report.json" >/dev/null

go run ./cmd/benchmark-report --manifest benchmark/manifest.json --format markdown > "$temporary_directory/report.md"
if ! cmp -s benchmark/REPORT.md "$temporary_directory/report.md"; then
  echo "benchmark/REPORT.md is stale; regenerate it from cmd/benchmark-report" >&2
  diff -u benchmark/REPORT.md "$temporary_directory/report.md" >&2 || true
  exit 1
fi

go run ./cmd/benchmark-report --manifest benchmark/manifest.json --format json > "$temporary_directory/repeat.json"
if ! cmp -s "$temporary_directory/report.json" "$temporary_directory/repeat.json"; then
  echo "inert benchmark report is not deterministic" >&2
  exit 1
fi

echo "inert benchmark: 4 declared cases matched; historical entries remain projection only"
