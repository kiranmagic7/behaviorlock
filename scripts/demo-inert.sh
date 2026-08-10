#!/bin/sh
set -eu

repository_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
temporary_directory="$(mktemp -d)"
cleanup_demo() {
  rm -rf -- "$temporary_directory"
}
trap cleanup_demo EXIT HUP INT TERM

behaviorlock_binary="${BEHAVIORLOCK_BIN:-$temporary_directory/behaviorlock}"
if [ -z "${BEHAVIORLOCK_BIN:-}" ]; then
  go build -trimpath -o "$behaviorlock_binary" "$repository_root/cmd/behaviorlock"
fi

baseline_profile="$temporary_directory/baseline.profile.json"
candidate_profile="$temporary_directory/candidate.profile.json"

printf 'BehaviorLock inert demo: replaying two handwritten offline traces.\n'
"$behaviorlock_binary" profile \
  --package demo-safe@1.0.0 \
  --trace "$repository_root/benchmark/corpus/credential-network/baseline.strace" \
  --output "$baseline_profile" >/dev/null
"$behaviorlock_binary" profile \
  --package demo-safe@1.1.0 \
  --trace "$repository_root/benchmark/corpus/credential-network/candidate.strace" \
  --output "$candidate_profile" >/dev/null

"$behaviorlock_binary" validate --profile "$baseline_profile"
"$behaviorlock_binary" validate --profile "$candidate_profile"

printf '\nObserved difference (evidence, not a package verdict):\n\n'
"$behaviorlock_binary" compare \
  --allow-external \
  --baseline "$baseline_profile" \
  --candidate "$candidate_profile" \
  --format markdown \
  --fail-on none

printf '\nDemo complete. No package was downloaded or executed; temporary profiles and evidence were removed.\n'
