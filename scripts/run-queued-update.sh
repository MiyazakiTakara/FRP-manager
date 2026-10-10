#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
STATE_DIR="/var/lib/frp-manager"
REQUEST="$STATE_DIR/update-request"
STATUS="$STATE_DIR/update-status.json"
UPDATER="/usr/local/sbin/frp-manager-update"
[[ -e "$REQUEST" ]] || exit 0
rm -f "$REQUEST"
mkdir -p "$STATE_DIR"

write_state() {
  local state="$1" revision="$2" stamp
  stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"state":"%s","revision":"%s","updated_at":"%s"}\n' \
    "$state" "$revision" "$stamp" > "$STATUS.tmp"
  chmod 0644 "$STATUS.tmp"
  mv -f "$STATUS.tmp" "$STATUS"
}

write_state running ""
if "$UPDATER" --apply; then
  write_state success ""
else
  write_state failed ""
  exit 1
fi
