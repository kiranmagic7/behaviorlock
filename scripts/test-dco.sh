#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
checker="$script_dir/check-dco.sh"
fixture_repo="$(mktemp -d)"
proof_remote="$(mktemp -d)"
mock_bin="$(mktemp -d)"
trap 'rm -rf "$fixture_repo" "$proof_remote" "$mock_bin"' EXIT HUP INT TERM

git -C "$fixture_repo" init -q
git -C "$fixture_repo" config user.name "Fixture"
git -C "$fixture_repo" config user.email "fixture@example.invalid"

make_commit() {
  printf '%s\n' "$5" > "$fixture_repo/state"
  git -C "$fixture_repo" add state
  GIT_AUTHOR_NAME="$1" \
    GIT_AUTHOR_EMAIL="$2" \
    GIT_COMMITTER_NAME="$3" \
    GIT_COMMITTER_EMAIL="$4" \
    git -C "$fixture_repo" commit -q -m "$5" -m "$6"
  git -C "$fixture_repo" rev-parse HEAD
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    echo "expected command to fail: $*" >&2
    exit 1
  fi
}

run_checker() {
  (
    cd "$fixture_repo"
    "$checker" "$@"
  )
}

base_sha="$(make_commit \
  "Kiran" \
  "262980978+kiranmagic7@users.noreply.github.com" \
  "Kiran" \
  "262980978+kiranmagic7@users.noreply.github.com" \
  "base" \
  "Signed-off-by: Kiran <262980978+kiranmagic7@users.noreply.github.com>")"

exact_sha="$(make_commit \
  "Kiran" \
  "262980978+kiranmagic7@users.noreply.github.com" \
  "Kiran" \
  "262980978+kiranmagic7@users.noreply.github.com" \
  "exact signoff" \
  "Signed-off-by: Kiran <262980978+kiranmagic7@users.noreply.github.com>")"
run_checker "$base_sha" "$exact_sha" strict >/dev/null

squash_sha="$(make_commit \
  "kiranmagic7" \
  "kiranmagic@proton.me" \
  "GitHub" \
  "noreply@github.com" \
  "GitHub squash" \
  "Signed-off-by: Kiran <262980978+kiranmagic7@users.noreply.github.com>")"
expect_failure run_checker "$exact_sha" "$squash_sha" strict
run_checker "$exact_sha" "$squash_sha" github-squash >/dev/null

plain_committer_sha="$(make_commit \
  "kiranmagic7" \
  "kiranmagic@proton.me" \
  "Kiran" \
  "262980978+kiranmagic7@users.noreply.github.com" \
  "not a GitHub squash" \
  "Signed-off-by: Kiran <262980978+kiranmagic7@users.noreply.github.com>")"
expect_failure run_checker "$squash_sha" "$plain_committer_sha" github-squash

wrong_identity_sha="$(make_commit \
  "kiranmagic7" \
  "kiranmagic@proton.me" \
  "GitHub" \
  "noreply@github.com" \
  "wrong signed identity" \
  "Signed-off-by: Someone Else <someone@example.invalid>")"
expect_failure run_checker "$plain_committer_sha" "$wrong_identity_sha" github-squash

missing_sha="$(make_commit \
  "kiranmagic7" \
  "kiranmagic@proton.me" \
  "GitHub" \
  "noreply@github.com" \
  "missing signoff" \
  "No signoff is present.")"
expect_failure run_checker "$wrong_identity_sha" "$missing_sha" github-squash

valid_head_sha="$(make_commit \
  "kiranmagic7" \
  "kiranmagic@proton.me" \
  "GitHub" \
  "noreply@github.com" \
  "valid head after unsigned history" \
  "Signed-off-by: Kiran <262980978+kiranmagic7@users.noreply.github.com>")"
expect_failure run_checker "$wrong_identity_sha" "$valid_head_sha" github-squash
expect_failure run_checker "$base_sha" "$valid_head_sha" invalid-mode

git -C "$proof_remote" init --bare -q
git -C "$fixture_repo" remote add origin "$proof_remote"
source_tree="$(git -C "$fixture_repo" rev-parse "$exact_sha^{tree}")"
source_one="$(
  printf '%s\n\n%s\n' 'source one' 'Signed-off-by: Kiran <262980978+kiranmagic7@users.noreply.github.com>' |
    GIT_AUTHOR_NAME='Kiran' \
    GIT_AUTHOR_EMAIL='262980978+kiranmagic7@users.noreply.github.com' \
    GIT_COMMITTER_NAME='Kiran' \
    GIT_COMMITTER_EMAIL='262980978+kiranmagic7@users.noreply.github.com' \
    git -C "$fixture_repo" commit-tree "$source_tree" -p "$exact_sha"
)"
source_head="$(
  printf '%s\n\n%s\n' 'source two' 'Signed-off-by: Kiran <262980978+kiranmagic7@users.noreply.github.com>' |
    GIT_AUTHOR_NAME='Kiran' \
    GIT_AUTHOR_EMAIL='262980978+kiranmagic7@users.noreply.github.com' \
    GIT_COMMITTER_NAME='Kiran' \
    GIT_COMMITTER_EMAIL='262980978+kiranmagic7@users.noreply.github.com' \
    git -C "$fixture_repo" commit-tree "$source_tree" -p "$source_one"
)"
missing_trailer_squash="$(
  printf '%s\n\n%s\n' 'GitHub squash without a trailer' 'The source commits carry the exact DCO signoffs.' |
    GIT_AUTHOR_NAME='kiranmagic7' \
    GIT_AUTHOR_EMAIL='kiranmagic@proton.me' \
    GIT_COMMITTER_NAME='GitHub' \
    GIT_COMMITTER_EMAIL='noreply@github.com' \
    git -C "$fixture_repo" commit-tree "$source_tree" -p "$exact_sha"
)"
git -C "$fixture_repo" push -q origin "$source_head:refs/pull/31/head"

mock_response="$mock_bin/response.json"
# The generated mock must expand these variables when it runs, not while this test writes it.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'test "$1" = api' \
  'cat "$MOCK_GH_RESPONSE"' > "$mock_bin/gh"
chmod 0700 "$mock_bin/gh"
printf '[{"number":31,"merged_at":"2026-08-10T21:31:36Z","merge_commit_sha":"%s","base":{"sha":"%s"},"head":{"sha":"%s"}}]\n' \
  "$missing_trailer_squash" "$exact_sha" "$source_head" > "$mock_response"

run_checker_with_proof() {
  (
    cd "$fixture_repo"
    PATH="$mock_bin:$PATH" \
      GH_TOKEN='fixture-token' \
      GITHUB_REPOSITORY='fixture/behaviorlock' \
      MOCK_GH_RESPONSE="$mock_response" \
      "$checker" "$@"
  )
}

run_checker_with_proof "$exact_sha" "$missing_trailer_squash" github-squash >/dev/null

unsigned_source="$(
  printf '%s\n\n%s\n' 'unsigned source' 'No DCO signoff is present.' |
    GIT_AUTHOR_NAME='Kiran' \
    GIT_AUTHOR_EMAIL='262980978+kiranmagic7@users.noreply.github.com' \
    GIT_COMMITTER_NAME='Kiran' \
    GIT_COMMITTER_EMAIL='262980978+kiranmagic7@users.noreply.github.com' \
    git -C "$fixture_repo" commit-tree "$source_tree" -p "$exact_sha"
)"
unsigned_squash="$(
  printf '%s\n' 'GitHub squash of unsigned source' |
    GIT_AUTHOR_NAME='kiranmagic7' \
    GIT_AUTHOR_EMAIL='kiranmagic@proton.me' \
    GIT_COMMITTER_NAME='GitHub' \
    GIT_COMMITTER_EMAIL='noreply@github.com' \
    git -C "$fixture_repo" commit-tree "$source_tree" -p "$exact_sha"
)"
git -C "$fixture_repo" push -q origin "$unsigned_source:refs/pull/32/head"
printf '[{"number":32,"merged_at":"2026-08-10T21:31:36Z","merge_commit_sha":"%s","base":{"sha":"%s"},"head":{"sha":"%s"}}]\n' \
  "$unsigned_squash" "$exact_sha" "$unsigned_source" > "$mock_response"
expect_failure run_checker_with_proof "$exact_sha" "$unsigned_squash" github-squash

mismatched_tree="$(git -C "$fixture_repo" rev-parse "$missing_sha^{tree}")"
mismatched_squash="$(
  printf '%s\n' 'GitHub squash with the wrong tree' |
    GIT_AUTHOR_NAME='kiranmagic7' \
    GIT_AUTHOR_EMAIL='kiranmagic@proton.me' \
    GIT_COMMITTER_NAME='GitHub' \
    GIT_COMMITTER_EMAIL='noreply@github.com' \
    git -C "$fixture_repo" commit-tree "$mismatched_tree" -p "$exact_sha"
)"
git -C "$fixture_repo" push -q origin "$source_head:refs/pull/33/head"
printf '[{"number":33,"merged_at":"2026-08-10T21:31:36Z","merge_commit_sha":"%s","base":{"sha":"%s"},"head":{"sha":"%s"}}]\n' \
  "$mismatched_squash" "$exact_sha" "$source_head" > "$mock_response"
expect_failure run_checker_with_proof "$exact_sha" "$mismatched_squash" github-squash

echo "DCO checker tests passed"
