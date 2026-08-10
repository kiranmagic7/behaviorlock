#!/bin/sh
set -eu

if [ "$#" -gt 2 ]; then
  echo "usage: scripts/current-release-report.sh [SOURCE_SHA] [json|markdown]" >&2
  exit 2
fi

repository_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
source_sha="${1:-$(git -C "$repository_root" rev-parse origin/main)}"
report_format="${2:-markdown}"
repository="${GITHUB_REPOSITORY:-$(gh repo view kiranmagic7/behaviorlock --json nameWithOwner --jq .nameWithOwner)}"
report_token="${GH_TOKEN:-$(gh auth token)}"
temporary_directory="$(mktemp -d)"
cleanup_release_report() {
  rm -rf -- "$temporary_directory"
}
trap cleanup_release_report EXIT HUP INT TERM

case "$report_format" in
  json|markdown) ;;
  *) echo "report format must be json or markdown" >&2; exit 2 ;;
esac

GITHUB_REPOSITORY="$repository" GITHUB_SHA="$source_sha" GH_TOKEN="$report_token" \
  "$repository_root/scripts/collect-release-proofs.sh" "$temporary_directory/evidence.json"

cd "$repository_root"
go build -trimpath -o "$temporary_directory/release-report" ./cmd/release-report
"$temporary_directory/release-report" \
  --config config/release-proofs.json \
  --evidence "$temporary_directory/evidence.json" \
  --repository "$repository" \
  --source-sha "$source_sha" \
  --format "$report_format"
