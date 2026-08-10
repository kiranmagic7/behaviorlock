#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/verify-trusted-profile.sh BUNDLE.tar.gz" >&2
  exit 2
fi

: "${EXPECTED_REPOSITORY:?EXPECTED_REPOSITORY is required}"
: "${EXPECTED_SOURCE_SHA:?EXPECTED_SOURCE_SHA is required}"
: "${EXPECTED_SOURCE_REF:?EXPECTED_SOURCE_REF is required}"
: "${BEHAVIORLOCK_BIN:?BEHAVIORLOCK_BIN is required}"

bundle="$1"
test -s "$bundle"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

tar -tzf "$bundle" | LC_ALL=C sort > "$temporary/actual-files"
cat > "$temporary/expected-files" <<'EOF'
baseline.profile.json
baseline.profile.json.evidence.strace
candidate.profile.json
candidate.profile.json.evidence.strace
checksums.sha256
manifest.json
report.json
EOF
if ! diff -u "$temporary/expected-files" "$temporary/actual-files"; then
  echo "trusted profile bundle has an unexpected file set" >&2
  exit 1
fi

tar -xzf "$bundle" -C "$temporary"
(
  cd "$temporary"
  sha256sum --check checksums.sha256
)

jq -e \
  --arg repository "$EXPECTED_REPOSITORY" \
  --arg source_sha "$EXPECTED_SOURCE_SHA" \
  --arg source_ref "$EXPECTED_SOURCE_REF" '
    .schemaVersion == 1 and
    .repository == $repository and
    .workflow == ".github/workflows/trusted-profile.yml" and
    .sourceSha == $source_sha and
    .sourceRef == $source_ref and
    .workflowRef == ($repository + "/.github/workflows/trusted-profile.yml@" + $source_ref) and
    (.runId | test("^[0-9]+$")) and
    (.runAttempt | test("^[0-9]+$")) and
    (.runnerImage.id | test("^sha256:[0-9a-f]{64}$")) and
    .acquisition.networkMode == "registry-proxy-unix" and
    .acquisition.policyVersion == "npm-registry-connect-v1" and
    .acquisition.allowedAuthority == "registry.npmjs.org:443"
  ' "$temporary/manifest.json" >/dev/null

pair_id="$(jq -r .pairId "$temporary/manifest.json")"
pair="$(jq -ce --arg id "$pair_id" '.pairs[] | select(.id == $id)' config/trusted-capture-pairs.json)"
baseline_spec="$(printf '%s' "$pair" | jq -r .baseline)"
candidate_spec="$(printf '%s' "$pair" | jq -r .candidate)"
runner_ref="$(jq -r .runnerImage.reference "$temporary/manifest.json")"
runner_id="$(jq -r .runnerImage.id "$temporary/manifest.json")"

for side in baseline candidate; do
  if [ "$side" = baseline ]; then
    package_spec="$baseline_spec"
  else
    package_spec="$candidate_spec"
  fi
  package_name="${package_spec%@*}"
  package_version="${package_spec##*@}"
  profile="$temporary/$side.profile.json"
  jq -e \
    --arg name "$package_name" \
    --arg version "$package_version" \
    --arg purl "pkg:npm/$package_name@$package_version" \
    --arg runner_ref "$runner_ref" \
    --arg runner_id "$runner_id" '
      .subject.name == $name and
      .subject.version == $version and
      .subject.purl == $purl and
      .capture.runnerImage == $runner_ref and
      .capture.runnerImageId == $runner_id and
      .capture.traceIntegrity == "isolated-root-tracer" and
      .capture.acquisition.networkMode == "registry-proxy-unix" and
      .capture.acquisition.policyVersion == "npm-registry-connect-v1" and
      .capture.acquisition.allowedAuthority == "registry.npmjs.org:443" and
      .capture.acquisition.proxyRunnerImageId == $runner_id
    ' "$profile" >/dev/null
  if [ "$(stat -c '%a' "$profile.evidence.strace")" != "600" ]; then
    echo "$side evidence is not mode 0600" >&2
    exit 1
  fi
done

"$BEHAVIORLOCK_BIN" validate --profile "$temporary/baseline.profile.json"
"$BEHAVIORLOCK_BIN" validate --profile "$temporary/candidate.profile.json"
"$BEHAVIORLOCK_BIN" compare \
  --baseline "$temporary/baseline.profile.json" \
  --candidate "$temporary/candidate.profile.json" \
  --fail-on none \
  --format json \
  --output "$temporary/recomputed-report.json"
cmp "$temporary/report.json" "$temporary/recomputed-report.json"

gh attestation verify "$bundle" \
  --repo "$EXPECTED_REPOSITORY" \
  --signer-workflow "$EXPECTED_REPOSITORY/.github/workflows/trusted-profile.yml" \
  --source-digest "$EXPECTED_SOURCE_SHA" \
  --source-ref "$EXPECTED_SOURCE_REF" \
  --deny-self-hosted-runners \
  --format json > "$temporary/attestation-verification.json"
jq -e 'type == "array" and length > 0' "$temporary/attestation-verification.json" >/dev/null
