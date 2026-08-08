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
    cd /seed
    npm init --yes >/dev/null 2>&1
    npm install --ignore-scripts --save-exact --package-lock=true --no-audit --no-fund -- "$package_spec" >/tmp/behaviorlock-prepare.log 2>&1
    metadata="$(node /opt/behaviorlock/metadata.mjs "$package_spec")"
    printf 'BEHAVIORLOCK_PREP_V1 %s\n' "$metadata"
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
    strace -u scanner -ff -qq -s 4096 -yy \
      -e trace=%file,%process,%network \
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
    printf 'BEHAVIORLOCK_TRACE_V1\n'
    for trace_file in /trace/raw*; do
      [ -f "$trace_file" ] || continue
      cat "$trace_file"
    done
    printf '\nBEHAVIORLOCK_TRACE_END exit=%s\n' "$command_exit"
    ;;
  version)
    printf '{"node":"%s","npm":"%s","strace":"%s"}\n' \
      "$(node --version)" "$(npm --version)" "$(strace --version | sed -n '1s/^strace -- version //p')"
    ;;
  *)
    echo "usage: entrypoint.sh prepare|trace|version package@version" >&2
    exit 64
    ;;
esac
