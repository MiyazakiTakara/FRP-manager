#!/usr/bin/env bash
# Run from the checked-out, reviewed feature branch on FRP Manager LXC.
set -Eeuo pipefail
umask 077
[[ "${EUID}" -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }
[[ -f ui_store.py && -f scripts/update.sh && -f deploy/frp-manager-alert.timer ]] ||
  { echo "Run from a complete reviewed FRP-manager repository checkout" >&2; exit 1; }
getent passwd frpmanager-svc >/dev/null || { echo "Service user missing" >&2; exit 1; }
[[ -f /opt/frp-manager/sso_app.py ]] || { echo "Existing FRP Manager not found" >&2; exit 1; }
install -d -o frpmanager-svc -g frpmanager-svc -m 0700 /var/lib/frp-manager/ui
install -d -o root -g root -m 0700 /var/backups/frp-manager
install -o root -g root -m 0644 ui_store.py /opt/frp-manager/ui_store.py
# Preserve updater used by existing automatic deployment.
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
cp -a /usr/local/sbin/frp-manager-update "/var/backups/frp-manager/updater-before-v2-${stamp}" || true
install -o root -g root -m 0755 scripts/update.sh /usr/local/sbin/frp-manager-update
install -o root -g root -m 0755 scripts/alert-worker.py /usr/local/sbin/frp-manager-alert-worker
install -o root -g root -m 0755 scripts/auth-alert-worker.py /usr/local/sbin/frp-manager-auth-alert
install -o root -g root -m 0755 scripts/backup-config.py /usr/local/sbin/frp-manager-backup-config
for name in frp-manager-alert frp-manager-auth-alert frp-manager-backup; do
  install -o root -g root -m 0644 "deploy/${name}.service" "/etc/systemd/system/${name}.service"
  install -o root -g root -m 0644 "deploy/${name}.timer" "/etc/systemd/system/${name}.timer"
done
systemctl daemon-reload
/opt/frp-manager/venv/bin/python -m py_compile /opt/frp-manager/ui_store.py
echo "UI module and optional worker units installed. No timers enabled; no services restarted."
echo "Review feature PR, CI and root helper configuration before merging/deploying."
