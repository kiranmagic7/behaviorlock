#!/bin/sh
set -eu

temp_dir="$(mktemp -d)"
probe_proxy=""
probe_network=""
probe_volume=""
tracer_death_container=""
resource_container=""
cleanup_integration() {
  if [ -n "$probe_proxy" ]; then
    docker rm --force "$probe_proxy" >/dev/null 2>&1 || true
  fi
  if [ -n "$probe_volume" ]; then
    docker volume rm --force "$probe_volume" >/dev/null 2>&1 || true
  fi
  if [ -n "$probe_network" ]; then
    docker network rm "$probe_network" >/dev/null 2>&1 || true
  fi
  for test_container in "$tracer_death_container" "$resource_container"; do
    if [ -n "$test_container" ]; then
      docker rm --force "$test_container" >/dev/null 2>&1 || true
    fi
  done
  rm -rf "$temp_dir"
}
trap cleanup_integration EXIT
trap 'exit 130' HUP INT TERM
trace_output="$temp_dir/envelope.txt"
raw_trace="$temp_dir/raw.strace"
profile="$temp_dir/profile.json"
profile_evidence="$profile.evidence.strace"

run_trace_container() {
  runner_image="$1"
  container_name="${2:-}"
  if [ -n "$container_name" ]; then
    set -- --name "$container_name"
  else
    set -- --rm
  fi
  docker run "$@" \
    --network none \
    --read-only \
    --user 0:0 \
    --cap-drop ALL \
    --cap-add SETUID \
    --cap-add SETGID \
    --cap-add SYS_PTRACE \
    --security-opt no-new-privileges:true \
    --pids-limit 128 \
    --memory 512m \
    --memory-swap 512m \
    --cpus 1 \
    --ulimit nofile=1024:1024 \
    --ulimit nproc=128:128 \
    --ulimit fsize=67108864:67108864 \
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
    "$runner_image" trace behaviorlock-fixture@1.0.0
}

run_resource_trace_container() {
  fixture_mode="$1"
  container_name="$2"
  pids_limit=128
  nproc_limit=128
  memory_limit=256m
  nofile_limit=1024
  file_limit=67108864
  work_size=64m
  temporary_size=32m
  trace_size=64m
  case "$fixture_mode" in
    # The fixture applies a lower RLIMIT_NPROC after the package uid transition.
    # Keep container-wide headroom for the root-owned tracer and supervisor.
    process) pids_limit=128; nproc_limit=128; memory_limit=512m ;;
    descriptor) nofile_limit=64 ;;
    tmpfs) work_size=4m ;;
    # The fixture applies its smaller RLIMIT_FSIZE after uid transition so the
    # trusted tracer can retain the evidence needed to prove the boundary.
    file) ;;
    output) temporary_size=4m ;;
    syscall) trace_size=4m ;;
    timeout) ;;
    *) echo "unknown resource trace mode: $fixture_mode" >&2; return 64 ;;
  esac
  timeout --signal=TERM --kill-after=3 30 \
    docker run \
    --name "$container_name" \
    --network none \
    --read-only \
    --user 0:0 \
    --cap-drop ALL \
    --cap-add SETUID \
    --cap-add SETGID \
    --cap-add SYS_PTRACE \
    --security-opt no-new-privileges:true \
    --pids-limit "$pids_limit" \
    --memory "$memory_limit" \
    --memory-swap "$memory_limit" \
    --cpus 1 \
    --ulimit "nofile=$nofile_limit:$nofile_limit" \
    --ulimit "nproc=$nproc_limit:$nproc_limit" \
    --ulimit "fsize=$file_limit:$file_limit" \
    --ulimit core=0:0 \
    --shm-size 8m \
    --ipc none \
    --tmpfs "/work:rw,exec,nosuid,nodev,size=$work_size,uid=65532,gid=65532,mode=0700" \
    --tmpfs "/tmp:rw,exec,nosuid,nodev,size=$temporary_size,uid=0,gid=0,mode=1777" \
    --tmpfs /home/scanner:rw,nosuid,nodev,size=4m,uid=65532,gid=65532,mode=0700 \
    --tmpfs "/trace:rw,nosuid,nodev,noexec,size=$trace_size,uid=0,gid=0,mode=0700" \
    --env HOME=/home/scanner \
    --env npm_config_cache=/work/.npm-cache \
    --env npm_config_userconfig=/dev/null \
    --env npm_config_audit=false \
    --env npm_config_fund=false \
    --env npm_config_update_notifier=false \
    --env "BEHAVIORLOCK_RESOURCE_MODE=$fixture_mode" \
    --env HTTP_PROXY= \
    --env HTTPS_PROXY= \
    --env ALL_PROXY= \
    --env NO_PROXY= \
    --env http_proxy= \
    --env https_proxy= \
    --env all_proxy= \
    --env no_proxy= \
    behaviorlock-resource-fixture:dev trace behaviorlock-resource-fixture@1.0.0
}

remove_resource_container() {
  container_name="$1"
  docker rm --force "$container_name" >/dev/null 2>&1 || true
  if [ "$resource_container" = "$container_name" ]; then
    resource_container=""
  fi
}

require_resource_match() {
  pattern="$1"
  description="$2"
  output_file="$3"
  error_file="$4"
  if grep -Eq -- "$pattern" "$output_file"; then
    return
  fi
  echo "resource fixture check failed: $description" >&2
  echo "resource fixture stdout (tail):" >&2
  tail -120 "$output_file" >&2 || true
  echo "resource fixture stderr (tail):" >&2
  tail -120 "$error_file" >&2 || true
  exit 1
}

assert_no_capture_resources() {
  if docker ps -a --format '{{.Names}}' | grep -Eq '^behaviorlock-(prep|trace|proxy)-'; then
    echo "capture left an analysis container behind" >&2
    exit 1
  fi
  if docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -Eq '^behaviorlock-analysis:'; then
    echo "capture left a temporary image behind" >&2
    exit 1
  fi
  if docker volume ls --format '{{.Name}}' | grep -Eq '^behaviorlock-acq-socket-'; then
    echo "capture left an acquisition socket volume behind" >&2
    exit 1
  fi
  if docker network ls --format '{{.Name}}' | grep -Eq '^behaviorlock-acq-egress-'; then
    echo "capture left an acquisition egress network behind" >&2
    exit 1
  fi
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

require_profile_type() {
  behavior_type="$1"
  syscall_pattern="${2:-}"
  if jq -e --arg behavior_type "$behavior_type" '.behaviors | any(.type == $behavior_type)' "$profile" >/dev/null; then
    return
  fi
  echo "fixture profile check failed: missing $behavior_type" >&2
  jq -r '.behaviors[].type' "$profile" | sort -u >&2
  if [ -n "$syscall_pattern" ]; then
    echo "matching raw syscall lines:" >&2
    grep -E -- "$syscall_pattern" "$profile_evidence" | sed -n '1,20p' >&2 || true
  fi
  exit 1
}

docker build --pull=false --tag behaviorlock-runner-fixture:dev testdata/npm-fixture
run_trace_container behaviorlock-runner-fixture:dev > "$trace_output"

require_trace_match '^BEHAVIORLOCK_TRACE_V1$' 'missing trace header'
require_trace_match '^BEHAVIORLOCK_TRACE_END exit=0$' 'lifecycle or tracer returned nonzero'
require_trace_match '/proc/self/status' 'fixture did not inspect its effective capabilities'
require_trace_match '/trace.*(EACCES|EPERM)' 'package code was not denied access to the trace directory'
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

test -s "$profile_evidence"
if [ "$(stat -c '%a' "$profile_evidence")" != "600" ]; then
  echo "raw evidence companion permissions are not 0600" >&2
  exit 1
fi
tampered_evidence="$temp_dir/tampered.strace"
cp "$profile_evidence" "$tampered_evidence"
printf 'tampered\n' >> "$tampered_evidence"
if go run ./cmd/behaviorlock validate --profile "$profile" --evidence "$tampered_evidence" >/dev/null 2>&1; then
  echo "validate accepted tampered raw evidence" >&2
  exit 1
fi

require_profile_type 'network.connect'
# $HOME is the literal normalized path token in the JSON profile.
# shellcheck disable=SC2016
grep -q '"target": "$HOME/.ssh/id_rsa"' "$profile"
grep -q '"sensitive": true' "$profile"
grep -q '"target": "/bin/sh"' "$profile"
require_profile_type 'network.dns'
require_profile_type 'network.listen' 'listen\('
require_profile_type 'network.accept'
require_profile_type 'filesystem.descriptor_write'
require_profile_type 'filesystem.enumerate'
require_profile_type 'process.create'
require_profile_type 'process.ptrace'
require_profile_type 'environment.timing'
grep -q '"runtime": \[' "$profile"

baseline_profile="$temp_dir/baseline.profile.json"
candidate_profile="$temp_dir/candidate.profile.json"
diff_report="$temp_dir/diff.json"
go run ./cmd/behaviorlock profile \
  --package example@1.0.0 \
  --trace testdata/traces/baseline.strace \
  --output "$baseline_profile"
go run ./cmd/behaviorlock profile \
  --package example@1.1.0 \
  --trace testdata/traces/candidate.strace \
  --output "$candidate_profile"
go run ./cmd/behaviorlock compare \
  --allow-external \
  --baseline "$baseline_profile" \
  --candidate "$candidate_profile" \
  --format json \
  --fail-on none \
  --output "$diff_report"
grep -q '"reviewRequired": true' "$diff_report"
grep -q '"highestReviewLevel": "critical"' "$diff_report"
grep -q '"artifactSha256": "sha256:' "$diff_report"
grep -q '"lineSha256": "sha256:' "$diff_report"

direct_probe='
const net = require("node:net");
const targets = [
  ["registry.npmjs.org", 443],
  ["1.1.1.1", 443],
  ["10.0.0.1", 443],
  ["169.254.169.254", 80],
  ["172.17.0.1", 80],
];
async function isBlocked([host, port]) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const finish = (blocked) => {
      socket.destroy();
      resolve(blocked);
    };
    socket.once("connect", () => finish(false));
    socket.once("error", () => finish(true));
    socket.setTimeout(750, () => finish(true));
  });
}
(async () => {
  for (const target of targets) {
    if (!(await isBlocked(target))) process.exit(1);
  }
})().catch(() => process.exit(1));
'
if ! docker run --rm \
  --network none \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --entrypoint node \
  behaviorlock-runner:dev \
  -e "$direct_probe"; then
  echo "network-none preparation probe reached a direct destination" >&2
  exit 1
fi

network_suffix="$(basename "$temp_dir" | tr -cd 'a-zA-Z0-9')"
probe_proxy="behaviorlock-proxy-probe-$network_suffix"
probe_network="behaviorlock-acq-egress-probe-$network_suffix"
probe_volume="behaviorlock-acq-socket-probe-$network_suffix"
docker network create --driver bridge "$probe_network" >/dev/null
docker volume create --driver local "$probe_volume" >/dev/null
docker run --detach \
  --name "$probe_proxy" \
  --network "$probe_network" \
  --read-only \
  --user 0:0 \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add SETUID \
  --cap-add SETGID \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --memory 128m \
  --memory-swap 128m \
  --cpus 0.5 \
  --ulimit nofile=256:256 \
  --ulimit nproc=64:64 \
  --ulimit core=0:0 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=8m,uid=65532,gid=65532,mode=0700 \
  --mount "type=volume,source=$probe_volume,target=/proxy,volume-nocopy" \
  --env HTTP_PROXY= \
  --env HTTPS_PROXY= \
  --env ALL_PROXY= \
  --env NO_PROXY= \
  --env http_proxy= \
  --env https_proxy= \
  --env all_proxy= \
  --env no_proxy= \
  behaviorlock-runner:dev proxy >/dev/null
proxy_ready=false
proxy_attempt=0
while [ "$proxy_attempt" -lt 100 ]; do
  if docker logs "$probe_proxy" 2>/dev/null | grep -q '^BEHAVIORLOCK_PROXY_READY_V1 npm-registry-connect-v1 registry.npmjs.org:443$'; then
    proxy_ready=true
    break
  fi
  proxy_attempt=$((proxy_attempt + 1))
  sleep 0.05
done
if [ "$proxy_ready" != true ]; then
  echo "manual acquisition proxy did not become ready" >&2
  docker logs "$probe_proxy" >&2 || true
  exit 1
fi
if [ "$(docker exec "$probe_proxy" awk '/^Uid:/ { print $2 }' /proc/1/status)" != "65532" ]; then
  echo "acquisition proxy PID 1 did not drop to uid 65532" >&2
  exit 1
fi
if [ "$(docker exec "$probe_proxy" awk '/^CapEff:/ { print $2 }' /proc/1/status)" != "0000000000000000" ]; then
  echo "acquisition proxy retained effective capabilities" >&2
  exit 1
fi

proxy_client='
const net = require("node:net");
const authority = process.argv[1];
const expected = process.argv[2];
let response = "";
const socket = net.connect("/proxy/proxy.sock", () => {
  socket.write("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n\r\n");
});
socket.on("data", (chunk) => {
  response += chunk.toString("utf8");
  if (response.includes("\r\n\r\n")) socket.end();
});
socket.on("error", () => process.exit(1));
socket.setTimeout(10000, () => process.exit(1));
socket.on("close", () => process.exit(response.startsWith("HTTP/1.1 " + expected) ? 0 : 1));
'
for probe_case in 'attacker.invalid:443 403' 'registry.npmjs.org:443 200'; do
  # The values are fixed test cases, not untrusted input.
  # shellcheck disable=SC2086
  docker run --rm \
    --network none \
    --user 65532:65532 \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --mount "type=volume,source=$probe_volume,target=/proxy,readonly,volume-nocopy" \
    --entrypoint node \
    behaviorlock-runner:dev \
    -e "$proxy_client" $probe_case
done
docker rm --force "$probe_proxy" >/dev/null
probe_proxy=""
docker volume rm --force "$probe_volume" >/dev/null
probe_volume=""
docker network rm "$probe_network" >/dev/null
probe_network=""

capture_profile="$temp_dir/capture.profile.json"
go build -trimpath -o "$temp_dir/behaviorlock" ./cmd/behaviorlock
"$temp_dir/behaviorlock" capture \
  --experimental \
  --package is-number@7.0.0 \
  --timeout 3m \
  --output "$capture_profile"
"$temp_dir/behaviorlock" validate --profile "$capture_profile"
test -s "$capture_profile.evidence.strace"
grep -q '"traceIntegrity": "isolated-root-tracer"' "$capture_profile"
grep -q '"dependencyLockSha256": "sha256:' "$capture_profile"
grep -q '"networkMode": "registry-proxy-unix"' "$capture_profile"
grep -q '"policyVersion": "npm-registry-connect-v1"' "$capture_profile"
grep -q '"allowedAuthority": "registry.npmjs.org:443"' "$capture_profile"

assert_no_capture_resources

docker build --pull=false --tag behaviorlock-tracer-failure:dev testdata/tracer-failure
failure_output="$temp_dir/tracer-failure.out"
failure_error="$temp_dir/tracer-failure.err"
if run_trace_container behaviorlock-tracer-failure:dev > "$failure_output" 2> "$failure_error"; then
  echo "runner accepted tracer diagnostics as a complete capture" >&2
  exit 1
fi
grep -q 'strace reported diagnostics; capture is incomplete' "$failure_error"
if grep -q '^BEHAVIORLOCK_TRACE_END ' "$failure_output"; then
  echo "failed tracer emitted a trusted completion footer" >&2
  exit 1
fi

docker build --pull=false --tag behaviorlock-tracer-death:dev testdata/tracer-death
tracer_death_container="behaviorlock-tracer-death-$network_suffix"
tracer_death_output="$temp_dir/tracer-death.out"
tracer_death_error="$temp_dir/tracer-death.err"
set +e
run_trace_container behaviorlock-tracer-death:dev "$tracer_death_container" > "$tracer_death_output" 2> "$tracer_death_error"
tracer_death_exit=$?
set -e
if [ "$tracer_death_exit" -eq 0 ]; then
  echo "killing the real tracer unexpectedly produced a successful container" >&2
  exit 1
fi
grep -q 'BEHAVIORLOCK_REAL_TRACER_KILLED_V1' "$tracer_death_error"
if grep -Eq '^BEHAVIORLOCK_TRACE_(V1|END)' "$tracer_death_output"; then
  echo "real tracer death emitted a trusted envelope marker" >&2
  exit 1
fi
if [ "$(docker inspect --format '{{.State.Running}}' "$tracer_death_container")" != false ]; then
  echo "a tracee survived real tracer death" >&2
  exit 1
fi
docker rm --force "$tracer_death_container" >/dev/null
tracer_death_container=""

docker build --pull=false --tag behaviorlock-resource-fixture:dev testdata/resource-fixture
for fixture_mode in process descriptor tmpfs file output syscall; do
  echo "resource fixture: exercising $fixture_mode boundary"
  resource_container="behaviorlock-resource-$fixture_mode-$network_suffix"
  resource_output="$temp_dir/resource-$fixture_mode.out"
  resource_error="$temp_dir/resource-$fixture_mode.err"
  set +e
  run_resource_trace_container "$fixture_mode" "$resource_container" > "$resource_output" 2> "$resource_error"
  resource_exit=$?
  set -e
  resource_running="$(docker inspect --format '{{.State.Running}}' "$resource_container")"
  if [ "$resource_running" != false ]; then
    remove_resource_container "$resource_container"
    echo "$fixture_mode resource fixture required forced cleanup after its hard wall clock" >&2
    tail -120 "$resource_error" >&2 || true
    exit 1
  fi
  if [ "$resource_exit" -eq 124 ]; then
    remove_resource_container "$resource_container"
    echo "$fixture_mode resource fixture exceeded its hard wall clock" >&2
    tail -120 "$resource_error" >&2 || true
    exit 1
  fi
  case "$fixture_mode" in
    process)
      require_resource_match 'EAGAIN' 'process exhaustion did not expose EAGAIN' "$resource_output" "$resource_error"
      require_resource_match '/work/behaviorlock-process-fixture-started' 'process exhaustion fixture did not reach its marker' "$resource_output" "$resource_error"
      require_resource_match '^BEHAVIORLOCK_TRACE_END exit=[1-9][0-9]*$' 'process exhaustion did not produce a nonzero trusted footer' "$resource_output" "$resource_error"
      ;;
    descriptor)
      require_resource_match 'EMFILE' 'descriptor exhaustion did not expose EMFILE' "$resource_output" "$resource_error"
      require_resource_match '/work/behaviorlock-descriptor-boundary' 'descriptor exhaustion did not reach its marker' "$resource_output" "$resource_error"
      require_resource_match '^BEHAVIORLOCK_TRACE_END exit=[1-9][0-9]*$' 'descriptor exhaustion did not produce a nonzero trusted footer' "$resource_output" "$resource_error"
      ;;
    tmpfs)
      require_resource_match '/tmp/behaviorlock-tmpfs-boundary' 'tmpfs exhaustion did not reach its marker' "$resource_output" "$resource_error"
      require_resource_match '^BEHAVIORLOCK_TRACE_END exit=[1-9][0-9]*$' 'tmpfs exhaustion did not produce a nonzero trusted footer' "$resource_output" "$resource_error"
      ;;
    file)
      require_resource_match '/work/behaviorlock-file-limit' 'file-size fixture did not open its bounded target' "$resource_output" "$resource_error"
      require_resource_match 'EFBIG|SIGXFSZ' 'file-size exhaustion did not expose its kernel boundary' "$resource_output" "$resource_error"
      require_resource_match '^BEHAVIORLOCK_TRACE_END exit=[1-9][0-9]*$' 'file-size exhaustion did not produce a nonzero trusted footer' "$resource_output" "$resource_error"
      ;;
    output)
      require_resource_match '/work/behaviorlock-output-boundary' 'output exhaustion did not reach its marker' "$resource_output" "$resource_error"
      require_resource_match '^BEHAVIORLOCK_TRACE_END exit=[1-9][0-9]*$' 'output exhaustion did not produce a nonzero trusted footer' "$resource_output" "$resource_error"
      ;;
    syscall)
      if [ "$resource_exit" -eq 0 ] || grep -q '^BEHAVIORLOCK_TRACE_END ' "$resource_output"; then
        echo "syscall-volume exhaustion produced a trusted completion" >&2
        exit 1
      fi
      require_resource_match 'strace reported diagnostics|trace sentinel evidence is incomplete|No space left' 'syscall-volume exhaustion had no bounded failure diagnostic' "$resource_error" "$resource_output"
      ;;
  esac
  remove_resource_container "$resource_container"
done
if docker ps -a --format '{{.Names}}' | grep -Eq '^behaviorlock-(resource|tracer-death)-'; then
  echo "resource integration left a test container behind" >&2
  exit 1
fi

for control_mode in timeout oom output signal; do
  echo "control fixture: exercising $control_mode classification"
  control_image="behaviorlock-control-$control_mode:dev"
  docker build --pull=false \
    --build-arg "BEHAVIORLOCK_CONTROL_MODE=$control_mode" \
    --tag "$control_image" \
    testdata/control-runner
  control_profile="$temp_dir/control-$control_mode.profile.json"
  control_error="$temp_dir/control-$control_mode.err"
  control_timeout=2m
  expected_status=trace_incomplete
  case "$control_mode" in
    timeout) control_timeout=20s; expected_status=timed_out ;;
    oom) expected_status=resource_exhausted ;;
    output|signal) expected_status=trace_incomplete ;;
  esac
  set +e
  "$temp_dir/behaviorlock" capture \
    --experimental \
    --runner "$control_image" \
    --package is-number@7.0.0 \
    --timeout "$control_timeout" \
    --output "$control_profile" \
    > "$temp_dir/control-$control_mode.out" 2> "$control_error"
  control_exit=$?
  set -e
  if [ "$control_exit" -ne 2 ]; then
    echo "$control_mode controlled capture exited $control_exit instead of 2" >&2
    sed -n '1,120p' "$control_error" >&2
    exit 1
  fi
  if ! jq -e '.capture.acquisition.networkMode == "registry-proxy-unix" and (.subject.registryIntegrity | length > 0)' "$control_profile" >/dev/null; then
    echo "$control_mode controlled capture lost acquisition provenance" >&2
    jq . "$control_profile" >&2 || true
    sed -n '1,120p' "$control_error" >&2
    exit 1
  fi
  if ! jq -e --arg expected_status "$expected_status" '.result.status == $expected_status' "$control_profile" >/dev/null; then
    echo "$control_mode controlled capture produced the wrong result status" >&2
    jq .result "$control_profile" >&2 || true
    sed -n '1,120p' "$control_error" >&2
    exit 1
  fi
  case "$control_mode" in
    timeout) control_contract='.result.timedOut == true' ;;
    oom) control_contract='.result.message | contains("memory limit")' ;;
    output) control_contract='.result.truncated == true' ;;
    signal) control_contract='.result.message | contains("signal-style exit code 137")' ;;
  esac
  if ! jq -e "$control_contract" "$control_profile" >/dev/null; then
    echo "$control_mode controlled capture violated its result contract" >&2
    jq .result "$control_profile" >&2 || true
    sed -n '1,120p' "$control_error" >&2
    exit 1
  fi
  assert_no_capture_resources
  echo "control fixture: $control_mode classification passed"
done

repeat_dir="$temp_dir/repeatability"
mkdir -p "$repeat_dir"
repeat_lines="$repeat_dir/runs.jsonl"
: > "$repeat_lines"
reference_profile_digest=""
reference_behavior_digest=""
repeat_index=1
while [ "$repeat_index" -le 10 ]; do
  echo "repeatability fixture: run $repeat_index of 10"
  repeat_envelope="$repeat_dir/run-$repeat_index.envelope"
  repeat_raw="$repeat_dir/run-$repeat_index.strace"
  repeat_profile="$repeat_dir/run-$repeat_index.profile.json"
  run_trace_container behaviorlock-runner-fixture:dev > "$repeat_envelope"
  awk '
    /^BEHAVIORLOCK_TRACE_V1$/ { capture=1; next }
    /^BEHAVIORLOCK_TRACE_END exit=/ { capture=0 }
    capture { print }
  ' "$repeat_envelope" > "$repeat_raw"
  "$temp_dir/behaviorlock" profile \
    --package behaviorlock-fixture@1.0.0 \
    --trace "$repeat_raw" \
    --output "$repeat_profile" >/dev/null
  validation="$("$temp_dir/behaviorlock" validate --profile "$repeat_profile")"
  profile_digest="$(printf '%s\n' "$validation" | grep -Eo 'sha256:[0-9a-f]{64}' | tail -1)"
  behavior_digest="$(jq -S '[.behaviors[].id]' "$repeat_profile" | sha256sum | awk '{ print "sha256:" $1 }')"
  count_digest="$(jq -S '[.behaviors[] | {id, count}]' "$repeat_profile" | sha256sum | awk '{ print "sha256:" $1 }')"
  raw_digest="$(sha256sum "$repeat_raw" | awk '{ print "sha256:" $1 }')"
  jq -nc \
    --argjson run "$repeat_index" \
    --arg profileDigest "$profile_digest" \
    --arg behaviorDigest "$behavior_digest" \
    --arg countDigest "$count_digest" \
    --arg rawDigest "$raw_digest" \
    '{run: $run, profileDigest: $profileDigest, behaviorDigest: $behaviorDigest, countDigest: $countDigest, rawDigest: $rawDigest}' \
    >> "$repeat_lines"
  if [ "$repeat_index" -eq 1 ]; then
    reference_profile_digest="$profile_digest"
    reference_behavior_digest="$behavior_digest"
  elif [ "$profile_digest" != "$reference_profile_digest" ] || [ "$behavior_digest" != "$reference_behavior_digest" ]; then
    echo "trusted fixture repeatability changed semantic behavior" >&2
    jq -s . "$repeat_lines" >&2
    exit 1
  fi
  repeat_index=$((repeat_index + 1))
done
jq -s '{runs: ., profileDigestVariants: ([.[].profileDigest] | unique | length), behaviorDigestVariants: ([.[].behaviorDigest] | unique | length), countDigestVariants: ([.[].countDigest] | unique | length), rawDigestVariants: ([.[].rawDigest] | unique | length)}' \
  "$repeat_lines" > "$repeat_dir/report.json"
jq -e '.profileDigestVariants == 1 and .behaviorDigestVariants == 1 and (.runs | length) == 10' "$repeat_dir/report.json" >/dev/null
printf 'repeatability: 10 semantic runs stable; count variants=%s; raw variants=%s\n' \
  "$(jq -r '.countDigestVariants' "$repeat_dir/report.json")" \
  "$(jq -r '.rawDigestVariants' "$repeat_dir/report.json")"
