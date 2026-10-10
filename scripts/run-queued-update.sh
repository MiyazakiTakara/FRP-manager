#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
STATE_DIR="/var/lib/frp-manager"
REQUEST="$STATE_DIR/update-request"
STATUS="$STATE_DIR/update-status.json"
PAUSED="$STATE_DIR/update-auto-paused"
REVISION="$STATE_DIR/deployed-revision"
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
  rm -f "$PAUSED"
  current="$(cat "$REVISION" 2>/dev/null || true)"
  write_state success "$current"
else
  printf "Last update failed at %s UTC\n" "$(date -u +%FT%TZ)" > "$PAUSED"
  write_state failed ""
  exit 1
fi
