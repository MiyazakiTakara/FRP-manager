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
