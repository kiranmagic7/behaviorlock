#!/bin/sh
set -eu

dist_dir="${1:-dist}"
if [ ! -d "$dist_dir" ]; then
  echo "release asset directory does not exist: $dist_dir" >&2
  exit 1
fi

archive_count=0
for operating_system in darwin linux; do
  for architecture in amd64 arm64; do
    matches="$(find "$dist_dir" -maxdepth 1 -type f -name "behaviorlock_*_${operating_system}_${architecture}.tar.gz" -print)"
    if [ "$(printf '%s\n' "$matches" | sed '/^$/d' | wc -l | tr -d ' ')" -ne 1 ]; then
      echo "expected one archive for $operating_system/$architecture" >&2
      exit 1
    fi
    archive="$matches"
    test -s "$archive"
    archive_count=$((archive_count + 1))

    if tar -tzf "$archive" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
      echo "archive contains an unsafe path: $archive" >&2
      exit 1
    fi
    listing="$(tar -tzf "$archive")"
    for required in behaviorlock LICENSE NOTICE README.md SECURITY.md; do
      if ! printf '%s\n' "$listing" | grep -Eq "/${required}$"; then
        echo "archive is missing $required: $archive" >&2
        exit 1
      fi
    done

    sbom="$archive.spdx.json"
    test -s "$sbom"
    jq -e '.spdxVersion | startswith("SPDX-")' "$sbom" >/dev/null
  done
done

if [ "$archive_count" -ne 4 ]; then
  echo "expected four release archives" >&2
  exit 1
fi

checksum_file="$dist_dir/behaviorlock_checksums.txt"
test -s "$checksum_file"
(
  cd "$dist_dir"
  sha256sum --check "$(basename "$checksum_file")"
)
