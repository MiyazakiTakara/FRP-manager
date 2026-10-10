# SQLite configuration history — phase 1

Configuration snapshots are stored in `/var/lib/frp-manager/history.db`.
This file is root-only (0600) and contains the complete FRPC configuration,
including credentials. Never publish, commit, attach or expose this database.

A separate sanitized `history-public.json` export contains only basic proxy
fields and change metadata. The authenticated UI is available at `/history`,
and JSON at `/api/history`. It never reads the raw SQLite database.

## First-time rollout (FRPC host)

This first stage adds baseline snapshot and automatic versions for successful
Create/Edit/Delete operations. **Restore is not implemented yet.**

The web application and root worker are deployed separately. Deploy the
current application via the normal application update mechanism, then use:

```bash
sudo systemctl stop frp-manager-tunnel-apply.path
cd /root/FRP-manager-github
git pull --ff-only origin main
python3 -m py_compile scripts/apply-tunnel.py
test ! -e /var/lib/frp-manager/tunnel-create-request.json
sudo install -o root -g root -m 0755 scripts/apply-tunnel.py /usr/local/sbin/frp-manager-apply-tunnel
sudo /usr/local/sbin/frp-manager-apply-tunnel --init-history
sudo systemctl reset-failed frp-manager-tunnel-apply.service
sudo systemctl start frp-manager-tunnel-apply.path
```

If the queue is not empty, stop and inspect it; do not restart the watcher.
The initialization step never restarts FRPC or changes its configuration.
The first snapshot is of the **current** configuration, not reconstructed past
edits. Older backup files are not imported or assigned invented authors.

Check:

```bash
sudo stat -c '%a %U %G %n' /var/lib/frp-manager/history.db
sudo test -f /var/lib/frp-manager/history-public.json
sudo systemctl is-active frpc frp-manager frp-manager-tunnel-apply.path
```

Ensure the web application has received the matching commit before testing
the History link. Do not paste the database or raw `frpc.toml` in issues or
support messages because both contain secrets.

## Consistency and safety

- The worker checks the most recent recorded snapshot hash against the
  current FRPC configuration before any new Create/Edit/Delete.
- An external/manual edit causes write operations to stop rather than silently
  creating a misleading version. A reconciliation workflow is a later phase.
- A commit is recorded after successful FRPC health checks.
- Export is capped at 100 recent versions. Full versions remain in SQLite.
- Changes to unrelated TOML settings are never included in the public diff.
- Operations are serialized by the existing root worker lock.
- History backups must be made using SQLite's online backup API (or a
  filesystem snapshot that consistently includes the database). Do not rely
  on copying a live SQLite file while writes are in progress.
- Root compromise can change both snapshots and hashes; this is not an
  immutable off-host audit trail.

**Known limitations:** author is shown as `panel-admin` rather than a
verified Keycloak identity; no restore UI, no external-change reconciliation,
and no failure-attempt audit trail are available in phase 1. These follow
after initial storage and history display are verified.
