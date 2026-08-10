#!/bin/sh
set -eu

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM
trace_output="$temp_dir/envelope.txt"
raw_trace="$temp_dir/raw.strace"
profile="$temp_dir/profile.json"
host_gateway="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
case "$host_gateway" in
  ''|*[!0-9.]*)
    echo "could not resolve the Docker bridge IPv4 gateway for the inert fixture" >&2
    exit 1
    ;;
esac

run_trace_container() {
  runner_image="$1"
  capability_mode="$2"
  case "$capability_mode" in
    with-ptrace)
      set -- --cap-add SYS_PTRACE
      ;;
    without-ptrace)
      set --
      ;;
    *)
      echo "unknown trace capability mode: $capability_mode" >&2
      exit 1
      ;;
  esac
  docker run --rm \
    --network none \
    --read-only \
    --user 0:0 \
    --cap-drop ALL \
    --cap-add SETUID \
    --cap-add SETGID \
    "$@" \
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
    --env HTTP_PROXY= \
    --env HTTPS_PROXY= \
    --env ALL_PROXY= \
    --env NO_PROXY= \
    --env http_proxy= \
    --env https_proxy= \
    --env all_proxy= \
    --env no_proxy= \
    --env "BEHAVIORLOCK_FIXTURE_HOST_GATEWAY=$host_gateway" \
    "$runner_image" trace behaviorlock-fixture@1.0.0
}

require_trace_match() {
  pattern="$1"
  description="$2"
  if grep -Eq -- "$pattern" "$trace_output"; then
    return
  fi
  echo "fixture trace check failed: $description" >&2
  sed -n '1,240p' "$trace_output" >&2
  exit 1
}

require_trace_count() {
  pattern="$1"
  expected="$2"
  description="$3"
  observed="$(grep -Ec -- "$pattern" "$trace_output" || true)"
  if [ "$observed" -eq "$expected" ]; then
    return
  fi
  echo "fixture trace count failed: $description; got $observed, want $expected" >&2
  sed -n '1,240p' "$trace_output" >&2
  exit 1
}

reject_trace_text() {
  forbidden_text="$1"
  description="$2"
  if ! grep -Fq -- "$forbidden_text" "$trace_output"; then
    return
  fi
  echo "fixture trace isolation failed: $description" >&2
  sed -n '1,240p' "$trace_output" >&2
  exit 1
}

require_profile_behavior() {
  profile_path="$1"
  behavior_type="$2"
  behavior_target="$3"
  behavior_outcome="$4"
  behavior_errno="$5"
  description="$6"
  if jq -e \
    --arg type "$behavior_type" \
    --arg target "$behavior_target" \
    --arg outcome "$behavior_outcome" \
    --arg errno "$behavior_errno" \
    'any(.behaviors[]; .type == $type and .target == $target and .outcome == $outcome and ($errno == "" or .errno == $errno))' \
    "$profile_path" >/dev/null; then
    return
  fi
  echo "fixture profile check failed: $description" >&2
  jq '.behaviors' "$profile_path" >&2
  exit 1
}

docker build --pull=false --tag behaviorlock-runner-fixture:dev testdata/npm-fixture
run_trace_container behaviorlock-runner-fixture:dev with-ptrace > "$trace_output"

require_trace_count '^BEHAVIORLOCK_TRACE_V1$' 1 'trusted trace header was missing or duplicated'
require_trace_count '^BEHAVIORLOCK_TRACE_END exit=' 1 'trusted trace footer was missing or duplicated'
require_trace_match '^BEHAVIORLOCK_TRACE_END exit=0$' 'lifecycle or tracer returned nonzero'
require_trace_match '/proc/self/status' 'fixture did not inspect its effective capabilities'
require_trace_match '/trace.*(EACCES|EPERM)' 'package code was not denied access to the trace directory'
require_trace_match '(sendto|sendmsg|sendmmsg)\(.*198\.51\.100\.2.* = -1 (EACCES|EPERM|ENETDOWN|ENETUNREACH|EHOSTUNREACH|ECONNREFUSED)' 'UDP probe was not blocked in the raw trace'
require_trace_match '(connect|sendto|sendmsg|sendmmsg)\(.*192\.0\.2\.53.* = -1 (EACCES|EPERM|ENETDOWN|ENETUNREACH|EHOSTUNREACH|ECONNREFUSED)' 'DNS probe was not blocked in the raw trace'
if grep -q 'BEHAVIORLOCK_CANARY_DO_NOT_USE' "$trace_output"; then
  echo "trace disclosed canary secret contents" >&2
  exit 1
fi
reject_trace_text '/tmp/behaviorlock-forged-syscall-marker' 'package output forged a syscall line'
reject_trace_text 'BEHAVIORLOCK_TRACE_END exit=99' 'package output forged a trace footer'
reject_trace_text 'BEHAVIORLOCK_FIXTURE_ANSI_PAYLOAD' 'package output entered the trace channel'
reject_trace_text 'BEHAVIORLOCK_FIXTURE_WORKFLOW_COMMAND' 'a workflow command entered the trace channel'
escape_character="$(printf '\033')"
if grep -Fq -- "$escape_character" "$trace_output"; then
  echo "fixture trace contained a raw terminal escape character" >&2
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

require_profile_behavior "$profile" 'filesystem.write' '/seed/behaviorlock-rootfs-write-probe' 'blocked' 'EROFS' 'read only image root did not return EROFS'
# $WORK is the literal normalized path token in the JSON profile.
# shellcheck disable=SC2016
require_profile_behavior "$profile" 'filesystem.write' '$WORK/behaviorlock-fixture-output' 'success' '' 'writable work tmpfs did not accept the fixture output'
# $HOME is the literal normalized path token in the JSON profile.
# shellcheck disable=SC2016
require_profile_behavior "$profile" 'filesystem.read' '$HOME/.ssh/id_rsa' 'success' '' 'fixture did not observe the decoy credential read'
if ! jq -e 'any(.behaviors[]; .target == "$HOME/.ssh/id_rsa" and .sensitive == true)' "$profile" >/dev/null; then
  echo "fixture profile did not mark the decoy credential path sensitive" >&2
  exit 1
fi
require_profile_behavior "$profile" 'process.exec' '/bin/sh' 'success' '' 'fixture shell was not observed'
require_profile_behavior "$profile" 'process.exec' '/bin/cat' 'success' '' 'native grandchild was not observed'
require_profile_behavior "$profile" 'network.connect' 'AF_INET:198.51.100.1:443' 'blocked' '' 'public TCP probe was not blocked'
require_profile_behavior "$profile" 'network.connect' 'AF_INET:10.0.0.1:443' 'blocked' '' 'private range TCP probe was not blocked'
require_profile_behavior "$profile" 'network.connect' "AF_INET:$host_gateway:443" 'blocked' '' 'Docker host gateway TCP probe was not blocked'
require_profile_behavior "$profile" 'network.connect' 'AF_INET:169.254.169.254:80' 'blocked' '' 'cloud metadata TCP probe was not blocked'

ptrace_failure_output="$temp_dir/no-ptrace.out"
ptrace_failure_error="$temp_dir/no-ptrace.err"
if run_trace_container behaviorlock-runner-fixture:dev without-ptrace > "$ptrace_failure_output" 2> "$ptrace_failure_error"; then
  echo "runner traced package code after SYS_PTRACE was removed" >&2
  exit 1
fi
grep -q 'strace reported diagnostics; capture is incomplete' "$ptrace_failure_error"
if grep -Eq '^BEHAVIORLOCK_TRACE_(V1|END )' "$ptrace_failure_output"; then
  echo "unsupported tracing emitted a trusted trace envelope" >&2
  exit 1
fi

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

docker build --pull=false --tag behaviorlock-tracer-failure:dev testdata/tracer-failure
failure_output="$temp_dir/tracer-failure.out"
failure_error="$temp_dir/tracer-failure.err"
if run_trace_container behaviorlock-tracer-failure:dev with-ptrace > "$failure_output" 2> "$failure_error"; then
  echo "runner accepted tracer diagnostics as a complete capture" >&2
  exit 1
fi
grep -q 'strace reported diagnostics; capture is incomplete' "$failure_error"
if grep -q '^BEHAVIORLOCK_TRACE_END ' "$failure_output"; then
  echo "failed tracer emitted a trusted completion footer" >&2
  exit 1
fi
