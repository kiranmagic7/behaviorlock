#!/bin/sh
set -eu

base_sha="${1:-}"
head_sha="${2:-}"
zero_sha="0000000000000000000000000000000000000000"

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
  if ! git show -s --format=%B "$commit_sha" | git interpret-trailers --parse | grep -Fqx "Signed-off-by: $author_name <$author_email>"; then
    echo "missing DCO signoff: $commit_sha $author_name" >&2
    exit 1
  fi
done < "$commit_list"
