#!/bin/sh
set -eu

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
checker="$script_dir/check-dco.sh"
fixture_repo="$(mktemp -d)"
trap 'rm -rf "$fixture_repo"' EXIT HUP INT TERM

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

echo "DCO checker tests passed"
