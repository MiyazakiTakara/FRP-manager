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


## Follow-up release: audit, backup, and session refresh

The root worker now records successful and failed operations in a separate
`operation_events` table. The authenticated History page displays the most
recent 100 events, while configuration versions are still created **only**
after successful health checks. Failed operations from before this upgrade
cannot be reconstructed reliably.

An administrator can verify snapshot hashes against the live configuration
without modifying FRPC:

```bash
/usr/local/sbin/frp-manager-apply-tunnel --verify-history
```

Create a consistent, root-only online SQLite backup (never just copy the
live database while a transaction may be running):

```bash
/usr/local/sbin/frp-manager-apply-tunnel --backup-history
```

The backup is under `/var/backups/frp-manager/history` and contains the
entire configuration including credentials. Back it up off-host securely.

The application session store also supports an encrypted OIDC refresh token,
if Keycloak returns one. It refreshes shortly before access-token expiry;
old sessions without refresh tokens continue to use their previous behavior.
Idle browser sessions still expire after 30 minutes. The persistent session
database has an additive migration for `encrypted_refresh_token`.

## Safe upgrade

For first rollout, stop `frp-manager-tunnel-apply.path`, update the working
copy and run `python3 -m py_compile scripts/apply-tunnel.py` and the offline
tests (`python3 -m unittest discover -s tests -v`). Verify the request queue
is empty, install the worker, run `--init-history`, then restart the path
unit. The application is separately updated by the existing web updater.
A normal worker upgrade requires **no FRPC restart**.

For changes with unsuccessful rollback, do not assume the configuration was
restored solely because the root worker stopped; inspect FRPC and SQLite
manually before allowing new writes.

The exact allowed-port policy for FRPS host `vps-01107d73` is available
as `deploy/allowed-ports-vps-01107d73.json`. Install it at
`/etc/frp-manager/allowed-ports.json` only if the remote FRPS rules remain
unchanged.


## Restore API (pre-GUI phase)

A guarded restore engine has been added, **disabled by default**. The code
requires all of the following for a write:

- A live authenticated `frp-admin` Keycloak session and a fresh CSRF token.
- Same-origin POST, exact request fields and an exclusive systemd queue slot.
- The existing `tunnel-writes-enabled` marker **and** a separate root-owned
  `/etc/frp-manager/tunnel-restore-enabled` marker. The latter must be
  intentionally created by the server administrator; do not create it during
  routine deployments.
- The current raw FRPC SHA-256 exactly matching the preview's expected hash.
- The snapshot's stored SHA-256 matching its raw bytes, TOML parse success,
  and every restored TCP/UDP public port passing the configured FRPS policy.
- FRPC syntax verification, backup, restart, and health checks for the
  restored tunnels (and existing tunnels retained in the target).
- A successful restore creates a **new** SQLite version with action
  `restore`; older versions are never deleted.

The admin-only read API is
`GET /api/history/restore-preview/{version}`, and actual queued
submission is `POST /api/history/restore`. A CSRF token can be obtained from
`GET /api/history/restore-csrf`. There is intentionally no Restore button
yet; enable the feature only after staging integration tests and an off-host
backup. Do not test against the production `udp-8050` tunnel.

### Preconditions for user-interface phase

Before designing the main interface, verify:

1. Application and root worker are both at compatible commits.
2. `python3 -m unittest discover -s tests -v` succeeds on the host.
3. `--verify-history` reports a current SHA-256 match.
4. `--backup-history` creates a valid root-only SQLite backup.
5. `/etc/frp-manager/allowed-ports.json` matches real FRPS `allowPorts`.
6. All FRPC, manager, nginx and systemd watcher services are active.
7. Keycloak role checks, token-refresh and timeout redirects work in browser.
8. New Create/Edit/Delete actions append versions and audit entries; failure
   writes only an audit event and restores the previous configuration.
9. Restore remains disabled pending staged rollback/fault-injection tests.
10. An off-host recovery plan exists for secrets-bearing backups.

A running service and passing syntax checks do not constitute a complete
fault-injection test. In particular, user identity propagation has not yet
been verified by a new successful production tunnel operation.
