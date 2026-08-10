#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: scripts/build-trusted-profile-bundle.sh PAIR_ID OUTPUT_DIRECTORY" >&2
  exit 2
fi

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GITHUB_REF:?GITHUB_REF is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
: "${GITHUB_WORKFLOW_REF:?GITHUB_WORKFLOW_REF is required}"

pair_id="$1"
output_dir="$2"
mkdir -p "$output_dir"

pair="$(jq -ce --arg id "$pair_id" '.pairs[] | select(.id == $id)' config/trusted-capture-pairs.json)"
if [ -z "$pair" ]; then
  echo "trusted capture pair is not allowlisted" >&2
  exit 2
fi
baseline="$(printf '%s' "$pair" | jq -r .baseline)"
candidate="$(printf '%s' "$pair" | jq -r .candidate)"

runner_ref="behaviorlock-runner:trusted-$GITHUB_SHA"
docker build --pull=false --tag "$runner_ref" runner
runner_id="$(docker image inspect "$runner_ref" --format '{{.Id}}')"
case "$runner_id" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "runner did not resolve to a sha256 content ID" >&2; exit 1 ;;
esac

go build -trimpath \
  -ldflags "-s -w -X github.com/kiranmagic7/behaviorlock/internal/cli.injectedVersion=trusted-$GITHUB_SHA" \
  -o "$output_dir/behaviorlock" ./cmd/behaviorlock

for side in baseline candidate; do
  if [ "$side" = baseline ]; then
    package_spec="$baseline"
  else
    package_spec="$candidate"
  fi
  "$output_dir/behaviorlock" capture \
    --experimental \
    --runner "$runner_ref" \
    --package "$package_spec" \
    --timeout 3m \
    --output "$output_dir/$side.profile.json"
  "$output_dir/behaviorlock" validate --profile "$output_dir/$side.profile.json"
done

"$output_dir/behaviorlock" compare \
  --baseline "$output_dir/baseline.profile.json" \
  --candidate "$output_dir/candidate.profile.json" \
  --fail-on none \
  --format json \
  --output "$output_dir/report.json"

for profile in "$output_dir/baseline.profile.json" "$output_dir/candidate.profile.json"; do
  test "$(jq -r .capture.runnerImageId "$profile")" = "$runner_id"
  test "$(jq -r .capture.acquisition.policyVersion "$profile")" = "npm-registry-connect-v1"
  test "$(jq -r .capture.acquisition.allowedAuthority "$profile")" = "registry.npmjs.org:443"
done

for artifact in baseline.profile.json baseline.profile.json.evidence.strace candidate.profile.json candidate.profile.json.evidence.strace report.json; do
  sha256sum "$output_dir/$artifact"
done | sed "s#  $output_dir/#  #" > "$output_dir/checksums.sha256"

jq -n \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg workflow ".github/workflows/trusted-profile.yml" \
  --arg workflow_ref "$GITHUB_WORKFLOW_REF" \
  --arg source_sha "$GITHUB_SHA" \
  --arg source_ref "$GITHUB_REF" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg pair_id "$pair_id" \
  --arg runner_ref "$runner_ref" \
  --arg runner_id "$runner_id" '
    {
      schemaVersion: 1,
      repository: $repository,
      workflow: $workflow,
      workflowRef: $workflow_ref,
      sourceSha: $source_sha,
      sourceRef: $source_ref,
      runId: $run_id,
      runAttempt: $run_attempt,
      pairId: $pair_id,
      runnerImage: { reference: $runner_ref, id: $runner_id },
      acquisition: {
        networkMode: "registry-proxy-unix",
        policyVersion: "npm-registry-connect-v1",
        allowedAuthority: "registry.npmjs.org:443"
      }
    }
  ' > "$output_dir/manifest.json"
sha256sum "$output_dir/manifest.json" | sed "s#  $output_dir/#  #" >> "$output_dir/checksums.sha256"

(
  cd "$output_dir"
  tar \
    --sort=name \
    --mtime='UTC 1970-01-01' \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -czf trusted-profile.tar.gz \
    baseline.profile.json \
    baseline.profile.json.evidence.strace \
    candidate.profile.json \
    candidate.profile.json.evidence.strace \
    checksums.sha256 \
    manifest.json \
    report.json
)
