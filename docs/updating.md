# Updating FRP Manager

**Status:** Early implementation. The updater must be validated against a staging instance before enabling its web trigger on a production host.

The updater changes only `app.py`, `sso_app.py` and `session_store.py`. It keeps FRP configuration, Keycloak credentials, SSH keys, the SQLite database and the Python virtual environment intact.

## Prerequisites

- Linux systemd installation with a working FRP Manager service
- `git`, `curl`, `flock` and Python venv already available
- `FRPS_PUBLIC_HOST` set in `/etc/frp-manager/oidc.env`
- The installed application dependencies match `requirements.txt`
- A known-good VM or container snapshot for disaster recovery

## Install the command-line updater

From a trusted checkout of this repository:

```bash
sudo install -o root -g root -m 0755 scripts/update.sh /usr/local/sbin/frp-manager-update
sudo frp-manager-update --check
```

After reviewing the resulting source diff and confirming the candidate version is safe:

```bash
sudo frp-manager-update --apply
```

Backups are stored under `/var/backups/frp-manager`. The command waits for the local `/api/health` endpoint and automatically restores the previous three source files if startup fails. This is a **startup rollback**, not a database migration rollback and not a complete behavioral test.

## Web update trigger (administrator-only)

**Do not enable the web update path on a production host until it passes staging tests.**

```bash
sudo install -o root -g root -m 0755 scripts/run-queued-update.sh /usr/local/sbin/frp-manager-run-queued-update
sudo install -o root -g root -m 0644 deploy/frp-manager-update.path /etc/systemd/system/frp-manager-update.path
sudo install -o root -g root -m 0644 deploy/frp-manager-update.service /etc/systemd/system/frp-manager-update.service
sudo systemctl daemon-reload
sudo systemctl enable --now frp-manager-update.path
```

The application offers `/updates`, available only to users with the `frp-admin` role. The update button issues a same-origin POST with a CSRF token. The unprivileged application creates a fixed-name request file; a root-managed `systemd.path` starts a narrow, pre-installed update runner. The application never receives unrestricted sudo access.

**Security considerations:** Review trusted branch changes before deployment; protect GitHub maintainer accounts; avoid publishing unreviewed automatic updates to production. The update trigger intentionally only installs source from the configured repository.

## Operational notes

- Do not run `git pull` directly over the live application.
- Never store credentials or session databases inside the repository.
- Update the Python dependencies separately through a reviewed upgrade procedure.
- The first import from an existing installation can differ from your local configuration. Compare the files and test in staging first.


## Scheduled checks and automatic downloads

Update checks run through a separate root-owned systemd timer. They do **not**
install updates or restart FRP. By default the service checks every 30 minutes.
The timer wakes up once a minute and the checker enforces the configured
interval; the minimum configured interval is one minute.

When the source branch has changed, the checker can automatically download a
snapshot into `/var/cache/frp-manager/<commit>`. This snapshot is **not**
automatically executed or installed. The administrator still approves
installation through the web panel.

Install the checker **only after** updating the app source and checking that
the web panel still works:

```bash
cd /root/FRP-manager-github
git pull --ff-only origin main
sudo install -o root -g root -m 0755 scripts/check-updates.py /usr/local/sbin/frp-manager-check-updates
sudo install -o root -g root -m 0644 deploy/frp-manager-check.service /etc/systemd/system/frp-manager-check.service
sudo install -o root -g root -m 0644 deploy/frp-manager-check.timer /etc/systemd/system/frp-manager-check.timer
sudo install -d -o root -g root -m 0700 /var/cache/frp-manager
sudo systemctl daemon-reload
sudo systemctl enable --now frp-manager-check.timer
sudo systemctl start frp-manager-check.service
```

The **Updates** page lets administrators change the check interval (1–1440
minutes), enable or disable automatic downloads, and schedule an immediate check
(on the next timer tick). If an update installation fails, the queued update
runner writes a pause marker. Automatic installations then stop, but periodic version checks and downloads continue. An administrator can resume automatic installation with **Resume auto-install**.

The status API and the update controls require the Keycloak `frp-admin` role.
The application does not receive root permissions. The existing update service
continues to execute only the fixed, root-owned updater.

Keep the installed updater and queued runner synchronized with the source:

```bash
sudo install -o root -g root -m 0755 scripts/update.sh /usr/local/sbin/frp-manager-update
sudo install -o root -g root -m 0755 scripts/run-queued-update.sh /usr/local/sbin/frp-manager-run-queued-update
```

Only checked-in application source files are deployed. Python dependencies,
systemd units, configuration values, and the updater itself are not changed by
the web installer. They require explicitly reviewed operator updates.

## Optional automatic installation

The **Auto-install downloaded updates** checkbox is disabled by default.
Only a Keycloak user with the `frp-admin` role can enable it. This option
requires **Automatically download updates** to remain enabled.

When a newer GitHub commit is detected, the checker validates and downloads
it, then calls the fixed root-owned update runner. The updater verifies the
expected commit SHA, creates a backup and checks application startup,
unauthenticated API access controls, and read-only FRPC status. No FRP
configuration or tunnel services are restarted.

If a deployment fails, the runner writes an `update-auto-paused` marker.
Subsequent automatic installation attempts stop. Version checks and downloads continue at the configured interval, including detection of newer commits. An administrator must explicitly select **Resume auto-install** to unblock automatic deployment. Manual installation remains available, including
for recovery.

These tests do **not** prove a real interactive Keycloak login works; this
should be checked after upgrading the service, especially when SSO code
changes.

**Important:** auto-install trusts the repository's main branch. Enable it
only if GitHub write access is tightly controlled and reviewed changes are
required. For maximum stability, prefer a release branch or pinned signed
releases instead of automatically deploying every new main-branch commit.
