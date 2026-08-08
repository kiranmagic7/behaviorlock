#!/bin/sh
set -u

package_spec="${1:-}"
cat /opt/behaviorlock/sentinel-start >/dev/null || exit 70
set +e
npm rebuild --offline --foreground-scripts --no-audit --no-fund -- "$package_spec"
command_exit=$?
set -e
cat /opt/behaviorlock/sentinel-end >/dev/null || exit 71
exit "$command_exit"
