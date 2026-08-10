#!/bin/sh
set -eu

mode="${1:-}"
package_spec="${2:-}"

case "$mode" in
  prepare)
    if [ "$(id -u)" -ne 65532 ]; then
      echo "prepare mode must run as uid 65532" >&2
      exit 70
    fi
    rm -f /tmp/behaviorlock-relay-ready
    node /opt/behaviorlock/proxy-relay.mjs >/tmp/behaviorlock-relay.log 2>&1 &
    relay_pid=$!
    cleanup_relay() {
      kill "$relay_pid" 2>/dev/null || true
      wait "$relay_pid" 2>/dev/null || true
    }
    trap cleanup_relay EXIT
    trap 'exit 130' HUP INT TERM
    relay_ready=false
    relay_attempt=0
    while [ "$relay_attempt" -lt 100 ]; do
      if [ -f /tmp/behaviorlock-relay-ready ]; then
        relay_ready=true
        break
      fi
      relay_attempt=$((relay_attempt + 1))
      sleep 0.05
    done
    if [ "$relay_ready" != true ]; then
      echo "acquisition proxy relay did not become ready" >&2
      sed -n '1,20p' /tmp/behaviorlock-relay.log >&2
      exit 71
    fi
    cd /seed
    npm init --yes >/dev/null 2>&1
    npm install --ignore-scripts --save-exact --package-lock=true --no-audit --no-fund -- "$package_spec" >/tmp/behaviorlock-prepare.log 2>&1
    metadata="$(node /opt/behaviorlock/metadata.mjs "$package_spec")"
    printf 'BEHAVIORLOCK_PREP_V1 %s\n' "$metadata"
    cleanup_relay
    trap - EXIT HUP INT TERM
    ;;
  trace)
    if [ "$(id -u)" -ne 0 ]; then
      echo "trace supervisor must run as uid 0" >&2
      exit 70
    fi
    su -s /bin/sh scanner -c 'cp -a /seed/. /work/'
    # The child shell must expand HOME after su changes identity.
    # shellcheck disable=SC2016
    su -s /bin/sh scanner -c '
      mkdir -p "$HOME/.ssh" "$HOME/.aws" "$HOME/.docker" "$HOME/.config/gcloud" "$HOME/.npm"
      printf "BEHAVIORLOCK_CANARY_DO_NOT_USE\n" > "$HOME/.ssh/id_rsa"
      printf "BEHAVIORLOCK_CANARY_DO_NOT_USE\n" > "$HOME/.aws/credentials"
      printf "{\"auths\":{\"canary.invalid\":{\"auth\":\"BEHAVIORLOCK_CANARY\"}}}\n" > "$HOME/.docker/config.json"
      printf "//registry.npmjs.org/:_authToken=BEHAVIORLOCK_CANARY\n" > "$HOME/.npmrc"
      chmod 0400 "$HOME/.ssh/id_rsa" "$HOME/.aws/credentials" "$HOME/.docker/config.json" "$HOME/.npmrc"
    '
    set +e
    # The traced child shell expands its positional argument.
    # shellcheck disable=SC2016
    strace -u scanner -ff -qq -ttt -s 4096 -yy \
      -e trace=%file,%process,%network,ftruncate,mmap,getdents,getdents64,memfd_create,ptrace,clock_gettime,clock_getres,gettimeofday,time,nanosleep,clock_nanosleep,dup,dup2,dup3,fcntl,close \
      -o /trace/raw \
      -- /bin/sh -c 'exec /opt/behaviorlock/lifecycle.sh "$1" > /tmp/package-output.log 2>&1' \
      behaviorlock-lifecycle "$package_spec" \
      2> /tmp/strace-error.log
    command_exit=$?
    set -e
    if [ -s /tmp/strace-error.log ]; then
      echo "strace reported diagnostics; capture is incomplete" >&2
      sed -n '1,20p' /tmp/strace-error.log >&2
      exit 72
    fi
    trace_found=false
    for trace_file in /trace/raw*; do
      if [ -f "$trace_file" ]; then
        trace_found=true
        break
      fi
    done
    if [ "$trace_found" != true ]; then
      echo "strace did not produce a trace; capture is incomplete" >&2
      sed -n '1,20p' /tmp/strace-error.log >&2
      exit 72
    fi
    sentinel_start=false
    sentinel_end=false
    for trace_file in /trace/raw*; do
      [ -f "$trace_file" ] || continue
      if grep -F '/opt/behaviorlock/sentinel-start' "$trace_file" >/dev/null; then
        sentinel_start=true
      fi
      if grep -F '/opt/behaviorlock/sentinel-end' "$trace_file" >/dev/null; then
        sentinel_end=true
      fi
    done
    if [ "$sentinel_start" != true ] || [ "$sentinel_end" != true ]; then
      echo "trace sentinel evidence is incomplete" >&2
      exit 72
    fi
    printf 'BEHAVIORLOCK_TRACE_V1\n'
    merge_fifo="/trace/merge.$$"
    mkfifo "$merge_fifo"
    (
      for trace_file in /trace/raw*; do
        [ -f "$trace_file" ] || continue
        trace_pid="${trace_file##*.}"
        case "$trace_pid" in
          *[!0-9]*|'')
            echo "strace output filename did not contain a numeric pid" >&2
            exit 72
            ;;
        esac
        awk -v trace_pid="$trace_pid" '{ print "[pid " trace_pid "] " $0 }' "$trace_file" || exit 72
      done
    ) > "$merge_fifo" &
    merge_pid=$!
    if ! LC_ALL=C sort -s -n -k3,3 "$merge_fifo"; then
      kill "$merge_pid" 2>/dev/null || true
      wait "$merge_pid" 2>/dev/null || true
      echo "failed to merge per-process trace files" >&2
      exit 72
    fi
    if ! wait "$merge_pid"; then
      echo "failed to prefix per-process trace files" >&2
      exit 72
    fi
    rm -f "$merge_fifo"
    printf '\nBEHAVIORLOCK_TRACE_END exit=%s\n' "$command_exit"
    ;;
  proxy)
    if [ "$(id -u)" -ne 0 ]; then
      echo "proxy supervisor must start as uid 0" >&2
      exit 70
    fi
    chmod 0700 /proxy
    chown 65532:65532 /proxy
    exec setpriv \
      --reuid=65532 \
      --regid=65532 \
      --clear-groups \
      --inh-caps=-all \
      --ambient-caps=-all \
      --bounding-set=-all \
      --no-new-privs \
      node /opt/behaviorlock/proxy.mjs
    ;;
  version)
    printf '{"node":"%s","npm":"%s","strace":"%s"}\n' \
      "$(node --version)" "$(npm --version)" "$(strace --version | sed -n '1s/^strace -- version //p')"
    ;;
  *)
    echo "usage: entrypoint.sh prepare|trace|proxy|version package@version" >&2
    exit 64
    ;;
esac
