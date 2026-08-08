#!/bin/sh
set -eu

trace_prefix=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    shift
    trace_prefix="${1:-}"
    break
  fi
  shift
done

if [ -z "$trace_prefix" ]; then
  echo "fake tracer did not receive an output path" >&2
  exit 64
fi

printf '%s\n' \
  'openat(AT_FDCWD, "/opt/behaviorlock/sentinel-start", O_RDONLY) = 3' \
  'openat(AT_FDCWD, "/opt/behaviorlock/sentinel-end", O_RDONLY) = 3' \
  > "${trace_prefix}.1"
echo "simulated tracer diagnostic" >&2
exit 0
