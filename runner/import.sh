#!/bin/sh
set -u

package_spec="${1:-}"
package_name="${package_spec%@*}"
if [ -z "$package_name" ] || [ "$package_name" = "$package_spec" ]; then
  exit 64
fi
cat /opt/behaviorlock/sentinel-start >/dev/null || exit 70
cd /work || exit 72
set +e
node /opt/behaviorlock/import.mjs "$package_name"
command_exit=$?
set -e
cat /opt/behaviorlock/sentinel-end >/dev/null || exit 71
exit "$command_exit"
