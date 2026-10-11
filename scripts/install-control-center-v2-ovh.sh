#!/usr/bin/env bash
# Run from a reviewed checkout on OVH, as root.
set -Eeuo pipefail
umask 077
[[ "${EUID}" -eq 0 ]] || { echo "Must run as root" >&2; exit 1; }
[[ -f /etc/frp/frps.toml ]] || { echo "No FRPS configuration on this host" >&2; exit 1; }
id frpmanager >/dev/null || { echo "Restricted SSH account is missing" >&2; exit 1; }
for entry in "scripts/frps-metrics.py:frp-manager-metrics" "scripts/frps-security-check.py:frp-manager-security-check"; do
  source_file="${entry%%:*}"
  target="${entry#*:}"
  [[ -f "${source_file}" ]] || { echo "Missing ${source_file}" >&2; exit 1; }
  install -o root -g root -m 0755 "${source_file}" "/usr/local/sbin/${target}"
  printf 'frpmanager ALL=(root) NOPASSWD: /usr/local/sbin/%s\n' "${target}" > "/etc/sudoers.d/${target}"
  chmod 0440 "/etc/sudoers.d/${target}"
  visudo -cf "/etc/sudoers.d/${target}"
done
install -o root -g root -m 0755 scripts/backup-config.py /usr/local/sbin/frp-manager-backup-config
install -d -o root -g root -m 0700 /var/backups/frp-manager
python3 -m py_compile /usr/local/sbin/frp-manager-metrics /usr/local/sbin/frp-manager-security-check
echo "Optional read-only OVH helpers installed. FRPS was NOT restarted or reconfigured."
echo "Traffic counters remain unavailable unless local FRPS dashboard is enabled."
