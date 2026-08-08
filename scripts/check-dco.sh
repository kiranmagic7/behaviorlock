#!/bin/sh
set -eu

base_sha="${1:-}"
head_sha="${2:-}"
mode="${3:-strict}"
zero_sha="0000000000000000000000000000000000000000"

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
        fi
        ;;
    esac
  fi

  echo "missing DCO signoff: $commit_sha $author_name" >&2
  exit 1
done < "$commit_list"
