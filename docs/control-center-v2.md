# FRP Manager Control Center v2 — staging and rollout

**Status: draft; not production deployed.** The feature branch is isolated from
`main` and must not be merged before CI, browser, role and rollback testing.
Never use the existing `udp-8050` proxy as a destructive test target.

## Delivered source components

- Native Add/Edit/Delete dialogs without iframe, form validation via the existing
  CSRF-protected API, before/after review, explicit name confirmation for delete,
  and operation status polling; root worker remains the authority for writes.
- Local TCP target probe restricted to existing configured proxies and admins.
  UDP returns `unsupported` rather than guessing reachability.
- Logical route Topology tab; never infer actual host uptime from proxy registration.
- Diagnostics/Security tab: selected local configuration checks, no secret output,
  FRPC TLS/bind visibility, root privilege enablement flags. No claim of full OVH audit.
- Tunnel labels/tags and time-bounded maintenance windows in an independent
  application metadata SQLite database. Maintenance **does not** stop tunnels.
- Opt-in alert worker with a single root-configured HTTPS webhook, failure
  deduplication and maintenance-window suppression.
- Backup script for LXC or FRPS: root-only archives including secrets, SQLite
  online snapshots on LXC, SHA-256 per member and offline `--verify`. No automatic
  extraction/restore. A backup copied off-host and a successful restore test are
  still required for disaster recovery.
- Optional FRPS read-only metric exporter: today traffic counters and active
  connections only if the FRPS authenticated server API is enabled; unreported
  counters remain absent. SSH helper is restricted to a fixed command.
- Side-by-side version metadata review, sanitized audit export explicitly marked
  **not a restorable backup**.
- CI syntax/unit tests including Node.js check of the *rendered* dashboard script.

## Safeguards and dependency installation

Do not enable `tunnel-writes-enabled`, `tunnel-manage-enabled`, or
`tunnel-restore-enabled` solely to test this UI.
New UI endpoints use existing Keycloak roles and origin/CSRF checks. They do
not start FRPC/FRPS or run shell commands with untrusted tunnel names.

The app's source updater in `scripts/update.sh` now installs
`ui_store.py` transactionally alongside the four existing Python modules.
**Install the new updater first** on LXC, before merging any change that imports
`ui_store`. Record the original updater and service status. The updater has its
own rollback, but cannot install new timers or VPS helper scripts.

Provision a separate metadata directory (not the FRPC configuration directory):
```sh
install -d -o frpmanager-svc -g frpmanager-svc -m 0700 /var/lib/frp-manager/ui
```
Metadata database path defaults to
`/var/lib/frp-manager/ui/state.db`; the service user needs write permission.
The app should never be granted write access to `/etc/frp/frpc.toml`.

Copy only the reviewed root helper scripts to these destinations if needed:
```sh
install -o root -g root -m 0755 scripts/alert-worker.py /usr/local/sbin/frp-manager-alert-worker
install -o root -g root -m 0755 scripts/backup-config.py /usr/local/sbin/frp-manager-backup-config
install -o root -g root -m 0644 deploy/frp-manager-alert.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/frp-manager-alert.timer /etc/systemd/system/
install -o root -g root -m 0644 deploy/frp-manager-backup.service /etc/systemd/system/
install -o root -g root -m 0644 deploy/frp-manager-backup.timer /etc/systemd/system/
install -d -o root -g root -m 0700 /var/backups/frp-manager
systemctl daemon-reload
```
Do not enable timers until their dry-run/one-shot checks pass.
The `/etc/frp-manager/alerts.env` file is optional and must be root:root 0600:
```sh
# An HTTPS Discord-compatible webhook. This is a secret.
FRP_ALERT_WEBHOOK_URL=https://example.invalid/replaced-by-private-webhook
```
The alert worker is deliberately a no-op without this variable. Test failure
and recovery using a synthetic snapshot in an isolated environment before
enabling the timer; do not bring down the production tunnel for testing.

For verified **local** backups run
```sh
python3 scripts/backup-config.py
python3 scripts/backup-config.py --verify /var/backups/frp-manager/<archive>.tgz
```
Archival files are 0600 and contain secrets; never serve them via HTTP.
Set up and verify separate off-host transfer and a restore rehearsal.
No automatic restore is enabled.

On **OVH FRPS**, only after review, install the exporter and scope the sudo
privilege to the one script:
```sh
sudo install -o root -g root -m 0755 scripts/frps-metrics.py /usr/local/sbin/frp-manager-metrics
echo 'frpmanager ALL=(root) NOPASSWD: /usr/local/sbin/frp-manager-metrics' | sudo tee /etc/sudoers.d/frp-manager-metrics >/dev/null
sudo chmod 0440 /etc/sudoers.d/frp-manager-metrics
sudo visudo -cf /etc/sudoers.d/frp-manager-metrics
```
This is a **separate** OVH action, not included in app auto-update.
The helper reads `/etc/frp/frps.toml`, authenticates to the FRPS *localhost*
dashboard, and emits bounded counters only. Do not expose the FRPS dashboard to
the public network. If no server dashboard is configured, the Traffic tab
truthfully shows unavailable. On OVH run the same backup utility with
`--scope frps` to archive `/etc/frp/frps.toml` and
`/etc/frp/server_token`, storing that archive root-only off-host.

## Release checklist

1. CI unit suite and Node.js syntax pass on the exact proposed commit.
2. Staging Keycloak role matrix: viewer cannot write/probe; operator may only
   preview new tunnel; admin can preview and request writes if root flags allow.
3. Empty Add form, malformed ports/IP/name, duplicate ports, concurrent request,
   timeout, CSRF failure, expired session and disabled root flags all render
   informative errors.
4. In a disposable test tunnel only: create, edit, delete; verify state,
   audited history, backup and rollback after an injected failure.
5. Confirm independent uptime and UDP application health are labeled unknown
   unless genuinely measured.
6. UI tags, maintenance date limits and alert silencing behave as specified.
7. Backup from a live SQLite WAL database verifies; restore a copy on an
   isolated LXC/VPS and document exact steps.
8. Ensure all new root/systemd services are disabled until explicitly enabled;
   verify `frpc.service`, `frps.service`, and existing `udp-8050` unchanged.
9. Confirm no role can read config tokens, webhooks, private archives or SSH keys.
10. Only then merge PR and roll out with the transactional updater.

## Unfinished integration dependencies

- A real UDP probe for Romestead requires a known application-level protocol,
  not blind UDP packet transmission.
- FRPS metrics require an enabled local dashboard and separately installed
  restricted SSH helper on the VPS. No synthetic transfer metrics.
- Alert webhook and off-host backup destination require operator configuration.
- Actual production deployment and disaster recovery verification require
  privileges/access not granted by the GitHub connector.

This file is deliberately explicit about unsupported and unverified areas.
