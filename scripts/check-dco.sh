#!/bin/sh
set -eu

base_sha="${1:-}"
head_sha="${2:-}"
mode="${3:-strict}"
zero_sha="0000000000000000000000000000000000000000"

valid_sha() {
  value="$1"
  [ "${#value}" -eq 40 ] || return 1
  case "$value" in
    *[!0-9a-f]*) return 1 ;;
  esac
}

verify_github_squash_provenance() {
  commit_sha="$1"
  parent_shas="$(git show -s --format=%P "$commit_sha")"
  case "$parent_shas" in
    ''|*' '*)
      echo "GitHub squash proof requires exactly one parent: $commit_sha" >&2
      return 1
      ;;
  esac
  parent_sha="$parent_shas"

  case "${GITHUB_REPOSITORY:-}" in
    ''|*[!A-Za-z0-9_./-]*|*/*/*|/*|*/)
      echo "GitHub squash proof has an invalid repository identity" >&2
      return 1
      ;;
    */*) ;;
    *)
      echo "GitHub squash proof has no repository identity" >&2
      return 1
      ;;
  esac
  if [ -z "${GH_TOKEN:-}" ] || ! command -v gh >/dev/null || ! command -v jq >/dev/null; then
    echo "GitHub squash proof requires GH_TOKEN, gh, and jq" >&2
    return 1
  fi

  pulls_json="$(gh api -H 'Accept: application/vnd.github+json' "repos/$GITHUB_REPOSITORY/commits/$commit_sha/pulls")" || {
    echo "GitHub squash proof could not read associated pull requests" >&2
    return 1
  }
  matches="$(printf '%s' "$pulls_json" | jq -c \
    --arg commit "$commit_sha" \
    --arg parent "$parent_sha" \
    '[.[] | select(.merged_at != null and .merge_commit_sha == $commit and .base.sha == $parent)]')" || {
    echo "GitHub squash proof response is invalid" >&2
    return 1
  }
  if [ "$(printf '%s' "$matches" | jq 'length')" -ne 1 ]; then
    echo "GitHub squash proof requires one exact merged pull request: $commit_sha" >&2
    return 1
  fi

  pull_number="$(printf '%s' "$matches" | jq -r '.[0].number')"
  source_base="$(printf '%s' "$matches" | jq -r '.[0].base.sha')"
  source_head="$(printf '%s' "$matches" | jq -r '.[0].head.sha')"
  case "$pull_number" in
    ''|*[!0-9]*)
      echo "GitHub squash proof has an invalid pull request number" >&2
      return 1
      ;;
  esac
  if ! valid_sha "$source_base" || ! valid_sha "$source_head" || [ "$source_base" != "$parent_sha" ]; then
    echo "GitHub squash proof has invalid source commits" >&2
    return 1
  fi

  git fetch --quiet --no-tags --no-recurse-submodules origin "refs/pull/$pull_number/head" || {
    echo "GitHub squash proof could not fetch pull request $pull_number" >&2
    return 1
  }
  fetched_head="$(git rev-parse --verify "FETCH_HEAD^{commit}")"
  if [ "$fetched_head" != "$source_head" ] || ! git merge-base --is-ancestor "$source_base" "$source_head"; then
    echo "GitHub squash proof source history does not match pull request $pull_number" >&2
    return 1
  fi
  if [ "$(git rev-parse "$source_head^{tree}")" != "$(git rev-parse "$commit_sha^{tree}")" ]; then
    echo "GitHub squash proof tree does not match pull request $pull_number" >&2
    return 1
  fi
  if ! "$0" "$source_base" "$source_head" strict >/dev/null; then
    echo "GitHub squash proof contains a source commit without an exact signoff" >&2
    return 1
  fi
  echo "accepted authenticated GitHub squash provenance: $commit_sha pull request $pull_number"
}

case "$mode" in
  strict|github-squash)
    ;;
  *)
    echo "invalid DCO verification mode" >&2
    exit 2
    ;;
esac

case "$head_sha" in
  ''|*[!0-9a-f]*)
    echo "invalid head commit" >&2
    exit 2
    ;;
esac
git rev-parse --verify --quiet "$head_sha^{commit}" >/dev/null || {
  echo "head commit does not exist" >&2
  exit 2
}

if [ "$base_sha" = "$zero_sha" ] || [ -z "$base_sha" ]; then
  revision_range="$head_sha"
else
  case "$base_sha" in
    *[!0-9a-f]*)
      echo "invalid base commit" >&2
      exit 2
      ;;
  esac
  git rev-parse --verify --quiet "$base_sha^{commit}" >/dev/null || {
    echo "base commit does not exist" >&2
    exit 2
  }
  revision_range="$base_sha..$head_sha"
fi

commit_list="$(mktemp)"
trap 'rm -f "$commit_list"' EXIT HUP INT TERM
git rev-list --reverse "$revision_range" > "$commit_list"

while IFS= read -r commit_sha; do
  author_name="$(git show -s --format=%an "$commit_sha")"
  author_email="$(git show -s --format=%ae "$commit_sha")"
  if git show -s --format=%B "$commit_sha" | git interpret-trailers --parse | grep -Fqx "Signed-off-by: $author_name <$author_email>"; then
    continue
  fi

  if [ "$mode" = "github-squash" ]; then
    committer_name="$(git show -s --format=%cn "$commit_sha")"
    committer_email="$(git show -s --format=%ce "$commit_sha")"
    case "$author_name" in
      ''|*[!A-Za-z0-9-]*|-*|*-)
        ;;
      *)
        if [ "$committer_name" = "GitHub" ] && [ "$committer_email" = "noreply@github.com" ]; then
          author_login="$(printf '%s' "$author_name" | tr '[:upper:]' '[:lower:]')"
          if git show -s --format=%B "$commit_sha" |
            git interpret-trailers --parse |
            sed -n 's/^Signed-off-by: [^<>][^<>]* <\([^<>][^<>]*\)>$/\1/p' |
            tr '[:upper:]' '[:lower:]' |
            grep -Eq "^([0-9]+\\+)?${author_login}@users\\.noreply\\.github\\.com$"; then
            echo "accepted authenticated GitHub squash signoff: $commit_sha $author_name"
            continue
          fi
          if verify_github_squash_provenance "$commit_sha"; then
            continue
          fi
        fi
        ;;
    esac
  fi

  echo "missing DCO signoff: $commit_sha $author_name" >&2
  exit 1
done < "$commit_list"
