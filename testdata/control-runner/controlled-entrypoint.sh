#!/bin/sh
set -eu

mode="${BEHAVIORLOCK_CONTROL_MODE:-}"
command_mode="${1:-}"
if [ "$command_mode" != trace ]; then
  exec /opt/behaviorlock/entrypoint.sh "$@"
fi

case "$mode" in
  timeout)
    exec sleep 60
    ;;
  oom)
    exec node -e 'const retained=[]; for (;;) retained.push(Buffer.alloc(16 * 1024 * 1024, 0x41));'
    ;;
  output)
    exec node -e 'const chunk=Buffer.alloc(1024 * 1024, 0x42); for (let i=0; i<80; i += 1) process.stdout.write(chunk);'
    ;;
  signal)
    # Exercise the signal-style exit-code classification deterministically.
    # Real tracer death is covered separately by the kill-real-strace fixture.
    exit 137
    ;;
  *)
    echo "unknown controlled runner mode: $mode" >&2
    exit 64
    ;;
esac
