#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
STATE_DIR="/var/lib/frp-manager"
REQUEST="$STATE_DIR/update-request"
STATUS="$STATE_DIR/update-status.json"
PAUSED="$STATE_DIR/update-auto-paused"
REVISION="$STATE_DIR/deployed-revision"
UPDATER="/usr/local/sbin/frp-manager-update"
MODE="${1:---manual}"
if [[ "$MODE" == "--auto" ]]; then
  [[ ! -e "$PAUSED" ]] || exit 0
  [[ "${FRP_EXPECTED_REVISION:-}" =~ ^[0-9a-f]{40}$ ]] || exit 2
elif [[ "$MODE" == "--manual" ]]; then
  [[ -e "$REQUEST" ]] || exit 0
  rm -f "$REQUEST"
else
  echo "Usage: run-queued-update [--manual|--auto]" >&2
  exit 2
fi
mkdir -p "$STATE_DIR"

write_state() {
  local state="$1" revision="$2" stamp
  stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local tmp
  tmp="$(mktemp "$STATE_DIR/.update-state.XXXXXXXX")"
  printf '{"state":"%s","revision":"%s","updated_at":"%s"}\n' \
    "$state" "$revision" "$stamp" > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$STATUS"
}

write_state running ""
if "$UPDATER" --apply; then
  if [[ "$MODE" == "--manual" ]]; then rm -f "$PAUSED"; fi
  current="$(cat "$REVISION" 2>/dev/null || true)"
  write_state success "$current"
else
  pause_tmp="$(mktemp "$STATE_DIR/.update-pause.XXXXXXXX")"
  printf "Last update failed at %s UTC\n" "$(date -u +%FT%TZ)" > "$pause_tmp"
  mv -f "$pause_tmp" "$PAUSED"
  write_state failed ""
  exit 1
fi
