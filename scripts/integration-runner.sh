#!/bin/sh
set -eu

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM
trace_output="$temp_dir/envelope.txt"
raw_trace="$temp_dir/raw.strace"
profile="$temp_dir/profile.json"

docker build --pull=false --tag behaviorlock-runner-fixture:dev testdata/npm-fixture

docker run --rm \
  --network none \
  --read-only \
  --user 0:0 \
  --cap-drop ALL \
  --cap-add SETUID \
  --cap-add SETGID \
  --security-opt no-new-privileges:true \
  --pids-limit 128 \
  --memory 512m \
  --memory-swap 512m \
  --cpus 1 \
  --ulimit nofile=1024:1024 \
  --ulimit nproc=128:128 \
  --ulimit core=0:0 \
  --shm-size 16m \
  --ipc none \
  --tmpfs /work:rw,exec,nosuid,nodev,size=384m,uid=65532,gid=65532,mode=0700 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=96m,uid=0,gid=0,mode=1777 \
  --tmpfs /home/scanner:rw,nosuid,nodev,size=8m,uid=65532,gid=65532,mode=0700 \
  --tmpfs /trace:rw,nosuid,nodev,noexec,size=128m,uid=0,gid=0,mode=0700 \
  --env HOME=/home/scanner \
  --env npm_config_cache=/work/.npm-cache \
  --env npm_config_userconfig=/dev/null \
  --env npm_config_audit=false \
  --env npm_config_fund=false \
  --env npm_config_update_notifier=false \
  behaviorlock-runner-fixture:dev trace behaviorlock-fixture@1.0.0 > "$trace_output"

grep -qx 'BEHAVIORLOCK_TRACE_V1' "$trace_output"
grep -Eq '^BEHAVIORLOCK_TRACE_END exit=0$' "$trace_output"
grep -Eq '/proc/self/status' "$trace_output"
grep -Eq '/trace.*(EACCES|EPERM)' "$trace_output"
if grep -q 'BEHAVIORLOCK_CANARY_DO_NOT_USE' "$trace_output"; then
  echo "trace disclosed canary secret contents" >&2
  exit 1
fi

awk '
  /^BEHAVIORLOCK_TRACE_V1$/ { capture=1; next }
  /^BEHAVIORLOCK_TRACE_END exit=/ { capture=0 }
  capture { print }
' "$trace_output" > "$raw_trace"

go run ./cmd/behaviorlock profile \
  --package behaviorlock-fixture@1.0.0 \
  --trace "$raw_trace" \
  --output "$profile"
go run ./cmd/behaviorlock validate --profile "$profile"

grep -q '"type": "network.connect"' "$profile"
# $HOME is the literal normalized path token in the JSON profile.
# shellcheck disable=SC2016
grep -q '"target": "$HOME/.ssh/id_rsa"' "$profile"
grep -q '"sensitive": true' "$profile"
grep -q '"target": "/bin/sh"' "$profile"

capture_profile="$temp_dir/capture.profile.json"
go build -trimpath -o "$temp_dir/behaviorlock" ./cmd/behaviorlock
"$temp_dir/behaviorlock" capture \
  --experimental \
  --package is-number@7.0.0 \
  --timeout 3m \
  --output "$capture_profile"
"$temp_dir/behaviorlock" validate --profile "$capture_profile"
grep -q '"traceIntegrity": "isolated-root-tracer"' "$capture_profile"
grep -q '"dependencyLockSha256": "sha256:' "$capture_profile"

if docker ps -a --format '{{.Names}}' | grep -Eq '^behaviorlock-(prep|trace)-'; then
  echo "capture left an analysis container behind" >&2
  exit 1
fi
if docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -Eq '^behaviorlock-analysis:'; then
  echo "capture left a temporary image behind" >&2
  exit 1
fi
