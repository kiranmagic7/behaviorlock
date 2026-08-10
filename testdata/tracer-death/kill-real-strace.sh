#!/bin/sh
set -u

/usr/bin/strace "$@" &
tracer_pid=$!
(
  sleep 0.10
  kill -KILL "$tracer_pid" 2>/dev/null || true
) &
killer_pid=$!

set +e
wait "$tracer_pid"
tracer_exit=$?
set -e
wait "$killer_pid" 2>/dev/null || true
echo "BEHAVIORLOCK_REAL_TRACER_KILLED_V1 pid=$tracer_pid exit=$tracer_exit" >&2
exit "$tracer_exit"
