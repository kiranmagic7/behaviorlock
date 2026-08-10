#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/record-inert-demo.sh OUTPUT.cast" >&2
  exit 2
fi
if ! command -v asciinema >/dev/null 2>&1; then
  echo "asciinema is required to record the demo" >&2
  exit 2
fi

repository_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
output="$1"
case "$output" in
  /*) ;;
  *) output="$PWD/$output" ;;
esac

cd "$repository_root"
exec asciinema rec \
  --overwrite \
  --idle-time-limit 1 \
  --title "BehaviorLock inert offline demo" \
  --command ./scripts/demo-inert.sh \
  "$output"
