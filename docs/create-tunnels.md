# Create Tunnel: safe application

This feature extends the read-only tunnel preview to an **administrator-only**
creation queue. It is disabled until explicitly activated on the host.

## Design

- The web process retains its unprivileged service account.
- A strict, fixed JSON envelope is queued in `/var/lib/frp-manager`.
- A dedicated root-owned `systemd.path` unit starts a one-shot worker.
- The worker independently validates the request, checks existing names and
  protocol/port conflicts, verifies the resulting TOML, takes a restrictive
  backup, restarts `frpc` and checks both the newly created proxy and all
  previously running proxies using the FRPC API.
- Failure after changing the file restores the previous configuration and
  restarts `frpc`.
- The new configuration is **not** applied until the operator explicitly
  creates `/etc/frp-manager/tunnel-writes-enabled`. Without it the API denies
  writes. The viewer and operator roles remain read-only for this action.
- This initial feature does not manage OVH firewall allow rules. Use an already
  allowed external port for the first end-to-end test.

## Bootstrap on the FRPC host

First verify the normal FRP Manager application update succeeded and that the
current Romestead tunnel remains healthy.

```bash
cd /root/FRP-manager-github
git pull --ff-only origin main

# Preflight the worker and check executable locations, without touching FRPC.
python3 -m py_compile scripts/apply-tunnel.py
command -v frpc
ls -l /etc/frp/frpc.toml

sudo install -o root -g root -m 0755 scripts/apply-tunnel.py /usr/local/sbin/frp-manager-apply-tunnel
sudo install -o root -g root -m 0644 deploy/frp-manager-tunnel-apply.service /etc/systemd/system/frp-manager-tunnel-apply.service
sudo install -o root -g root -m 0644 deploy/frp-manager-tunnel-apply.path /etc/systemd/system/frp-manager-tunnel-apply.path
sudo systemctl daemon-reload
sudo systemctl enable --now frp-manager-tunnel-apply.path
sudo systemctl is-active frp-manager-tunnel-apply.path
```

Leave the write marker **absent** initially. Verify the watcher is active and
the preview still works. Enable writes only after reviewing the worker and
the destination `frpc.toml`:

```bash
sudo install -o root -g root -m 0644 /dev/null /etc/frp-manager/tunnel-writes-enabled
```

To disable tunnel creation immediately:

```bash
sudo rm -f /etc/frp-manager/tunnel-writes-enabled
```

Do not test against a currently used external port. For the first real
creation, select a spare port already allowed by FRPS and its firewall.
Watch the result:

```bash
sudo journalctl -u frp-manager-tunnel-apply.service -n 70 --no-pager
sudo cat /var/lib/frp-manager/tunnel-create-status.json
sudo systemctl is-active frpc frp-manager
```

Backups are kept in `/var/backups/frp-manager/tunnels` with mode 0600.
The worker does not modify secrets, FRPS configuration or firewall rules.
Its status endpoint does not return backup file contents or tokens.

**Operational note:** source updates performed via the application's updater
do not install/update this root-owned worker or its systemd units. Apply
worker changes manually and review them before enabling writes.


## Edit and delete (second-stage activation)

The dashboard provides a read-only comparison first. Applying edits or deletions
is disabled by default, even when tunnel creation is already enabled. A separate,
root-owned enable marker is required.

After the latest application release is healthy, update the root-owned worker
**before** enabling Edit/Delete:

```bash
sudo systemctl stop frp-manager-tunnel-apply.path
cd /root/FRP-manager-github
git pull --ff-only origin main
python3 -m py_compile scripts/apply-tunnel.py
sudo install -o root -g root -m 0755 scripts/apply-tunnel.py /usr/local/sbin/frp-manager-apply-tunnel
sudo systemctl reset-failed frp-manager-tunnel-apply.service
sudo systemctl start frp-manager-tunnel-apply.path
```

Check that `/var/lib/frp-manager/tunnel-create-request.json` does not already
exist before restarting the watcher; if present, stop and inspect that queued
operation first.

Enable management only after verifying access controls and the existing
tunnels:

```bash
sudo install -o root -g root -m 0644 /dev/null /etc/frp-manager/tunnel-manage-enabled
```

Remove this marker to disable future Edit/Delete submissions:

```bash
sudo rm -f /etc/frp-manager/tunnel-manage-enabled
```

Edit is limited to target IPv4, local port and public port. Name and protocol
cannot be changed in this release. Advanced proxy blocks are rejected rather
than silently rewritten. Delete requires confirmation with the exact tunnel
name. Both operations preserve the rest of the configuration, use backups and
restore the previous configuration if verification fails. All changes restart
FRPC and can briefly interrupt existing tunnels.

Only `frp-admin` may apply changes; the root worker independently checks
the request against the live configuration. Test using a disposable TCP tunnel,
not the active game tunnel. A running proxy does not guarantee that its LAN
target service is reachable.
