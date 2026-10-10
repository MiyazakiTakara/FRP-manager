#!/usr/bin/env bash
# FRP Manager transactional source updater.
set -Eeuo pipefail
umask 077

REPO="https://github.com/MiyazakiTakara/FRP-manager.git"
BRANCH="main"
APP_DIR="/opt/frp-manager"
VENV_PY="$APP_DIR/venv/bin/python"
SERVICE="frp-manager.service"
BACKUP_DIR="/var/backups/frp-manager"
LOCK="/run/lock/frp-manager-update.lock"
FILES=(app.py sso_app.py session_store.py update_web.py)
MODE="${1:---check}"

if [[ "$MODE" != "--check" && "$MODE" != "--apply" ]]; then
  echo "Usage: frp-manager-update [--check|--apply]" >&2
  exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

exec 9>"$LOCK"
if ! flock -n 9; then
  echo "Another update is running." >&2
  exit 1
fi

for program in git systemctl curl timeout flock install; do
  command -v "$program" >/dev/null || { echo "Missing tool: $program" >&2; exit 1; }
done
[[ -x "$VENV_PY" ]] || { echo "Python venv not found: $VENV_PY" >&2; exit 1; }

WORK="$(mktemp -d /tmp/frp-manager-update.XXXXXXXX)"
trap 'rm -rf "$WORK"' EXIT
git clone --quiet --depth 1 --single-branch --branch "$BRANCH" "$REPO" "$WORK/repo"
REVISION="$(git -C "$WORK/repo" rev-parse HEAD)"
if [[ -n "${FRP_EXPECTED_REVISION:-}" && "$REVISION" != "$FRP_EXPECTED_REVISION" ]]; then
  echo "GitHub branch changed after download; retry on next check." >&2
  exit 3
fi

for name in "${FILES[@]}"; do
  [[ -f "$WORK/repo/$name" ]] || {
    echo "Missing source file: $name" >&2; exit 1;
  }
done

# Compile in an isolated staging directory without touching the running app.
mkdir "$WORK/stage"
for name in "${FILES[@]}"; do
  install -m 0644 "$WORK/repo/$name" "$WORK/stage/$name"
done
"$VENV_PY" -m compileall -q "$WORK/stage"

echo "Candidate commit: $REVISION"
echo "Files to update: ${FILES[*]}"
REVISION_FILE="/var/lib/frp-manager/deployed-revision"
if [[ -f "$REVISION_FILE" ]] && [[ "$(cat "$REVISION_FILE")" == "$REVISION" ]]; then
  echo "Already up to date. No restart required."
  exit 0
fi
echo "Runtime secrets, venv, SQLite and FRP configs will not be changed."

if [[ "$MODE" == "--check" ]]; then
  echo "Preflight passed. No changes made. Run: frp-manager-update --apply"
  exit 0
fi

# The published app requires the remote public hostname in the environment.
if ! grep -Eq '^FRPS_PUBLIC_HOST=.{1,}$' /etc/frp-manager/oidc.env; then
  echo "Missing FRPS_PUBLIC_HOST in /etc/frp-manager/oidc.env." >&2
  echo "Configure this first so the public tunnel address is not lost." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP="$BACKUP_DIR/$STAMP-$REVISION"
mkdir "$BACKUP"
chmod 0700 "$BACKUP"
for name in "${FILES[@]}"; do
  if [[ -f "$APP_DIR/$name" ]]; then
    cp -a "$APP_DIR/$name" "$BACKUP/$name"
  else
    touch "$BACKUP/$name.absent"
  fi
done

rollback() {
  echo "Health check failed. Rolling back source files..." >&2
  for name in "${FILES[@]}"; do
    if [[ -f "$BACKUP/$name.absent" ]]; then
      rm -f "$APP_DIR/$name"
    else
      install -m 0644 "$BACKUP/$name" "$APP_DIR/$name"
    fi
  done
  systemctl restart "$SERVICE" || true
}
for name in "${FILES[@]}"; do
  install -m 0644 "$WORK/stage/$name" "$APP_DIR/$name"
done

if ! systemctl restart "$SERVICE"; then
  rollback
  exit 1
fi

HEALTHY=0
for attempt in $(seq 1 20); do
  if curl --silent --show-error --fail --max-time 2 \
      http://127.0.0.1:8088/api/health 2>/dev/null \
      | grep -q '"status":"running"'; then
    HEALTHY=1
    break
  fi
  sleep 1
done

# Smoke-test protected APIs without a real session.
if [[ "$HEALTHY" -eq 1 ]]; then
  for endpoint in /api/tunnels /api/update/check; do
    status="$(curl --silent --output /dev/null --max-time 3 --write-out '%{http_code}' "http://127.0.0.1:8088$endpoint" || true)"
    if [[ "$status" != "401" ]]; then
      echo "Authorization check failed for $endpoint: $status" >&2
      HEALTHY=0
      break
    fi
  done
fi

# Functional FRPC integration check; no tunnel configuration changes.
if [[ "$HEALTHY" -eq 1 ]]; then
  if ! ( cd "$APP_DIR" && runuser -u frpmanager-svc -- "$VENV_PY" -c 'from app import get_tunnels; d=get_tunnels(); assert isinstance(d["tunnels"], list); assert d["monitoring"] == "available"' </dev/null ); then
    echo "FRPC read-only status test failed." >&2
    HEALTHY=0
  fi
fi

if [[ "$HEALTHY" -ne 1 ]]; then
  rollback
  echo "Update failed and previous files were restored." >&2
  exit 1
fi

printf '%s\n' "$REVISION" > "$BACKUP/deployed-commit"
REV_TMP="$(mktemp /var/lib/frp-manager/.revision.XXXXXXXX)"
printf '%s\n' "$REVISION" > "$REV_TMP"
chmod 0644 "$REV_TMP"
mv -f "$REV_TMP" "$REVISION_FILE"
echo "Update successful: $REVISION"
echo "Backup: $BACKUP"
