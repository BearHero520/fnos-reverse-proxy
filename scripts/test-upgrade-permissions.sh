#!/bin/bash
set -euo pipefail
[ "$(id -u)" = 0 ] || exit 1
source_script="$(readlink -f "$1")"
fixture="$(mktemp -d /opt/reverse-proxy-permission-test.XXXXXX)"
trap 'case "$fixture" in /opt/reverse-proxy-permission-test.*) rm -rf -- "$fixture" ;; esac' EXIT
mkdir -p "$fixture"/{cmd,config,app/server/lib,app/deployment-runtime/x64,app/deployment-runtime/arm64,var/data}
for name in server/fnos-deployer-helper.js server/lib/fnos-deployment-engine.js server/package.json deployment-runtime/x64/node deployment-runtime/arm64/node; do
  printf 'test-code' > "$fixture/app/$name"
  (cd "$fixture/app" && sha256sum "$name") >> "$fixture/config/deployment.sha256"
done
printf 'preserved-settings' > "$fixture/var/data/config.json"
printf 'preserved-log' > "$fixture/var/service.log"
chmod -R 700 "$fixture/var"
chmod 755 "$fixture"
setfacl -R -m u:reverse-proxy:rwx "$fixture/app"
# Load the exact production migration function without dispatching lifecycle.
source <(sed '/^case "${1:-}" in/,$d' "$source_script")
TASK_CMD="$fixture/cmd"
TRIM_APPDEST="$fixture/app"
TRIM_PKGVAR="$fixture/var"
prepare_permissions
runuser -u reverse-proxy -- test -r "$fixture/var/data/config.json"
runuser -u reverse-proxy -- test -w "$fixture/var/data/config.json"
runuser -u reverse-proxy -- test -w "$fixture/var/service.log"
if runuser -u reverse-proxy -- test -w "$fixture/app/server/fnos-deployer-helper.js"; then exit 1; fi
[ "$(cat "$fixture/var/data/config.json")" = preserved-settings ]
[ "$(cat "$fixture/var/service.log")" = preserved-log ]
prepare_permissions
printf 'tampered' > "$fixture/app/deployment-runtime/x64/node"
if prepare_permissions >/dev/null 2>&1; then echo 'tampered runtime accepted'; exit 1; fi
printf 'PASS: root-owned upgrade data recovered; code writes denied; repeat safe; tampering rejected\n'
