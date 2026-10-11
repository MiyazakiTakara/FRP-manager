# Security Events: OVH FRPS -> FRP Manager

**State:** backend code committed; deployment and end-to-end checks are required.

The existing SSH connection used for FRPS status is reused. No additional
firewall port, FRPS restart, packet capture or tunnel reconfiguration is needed.

## OVH deployment (SSH as ubuntu, sudo available)

From the checkout of this repository, copy `scripts/frps-security-events.py`
to the OVH server and install it root-owned as
`/usr/local/sbin/frp-manager-security-events`, executable 0755.

Example on OVH if the script was already copied to `/tmp/frps-security-events.py`:

```sh
sudo install -o root -g root -m 0755 /tmp/frps-security-events.py /usr/local/sbin/frp-manager-security-events
sudo /usr/local/sbin/frp-manager-security-events | python3 -m json.tool | head -n 60
```

The FRP Manager SSH account (default `frpmanager`) should get narrowly
scoped sudo permission for **only** this program. For an existing sudoers
file, append a separate drop-in without modifying permissions for other
FRPS status operations:

```sh
echo 'frpmanager ALL=(root) NOPASSWD: /usr/local/sbin/frp-manager-security-events' |
    sudo tee /etc/sudoers.d/frp-manager-security-events >/dev/null
sudo chmod 0440 /etc/sudoers.d/frp-manager-security-events
sudo visudo -cf /etc/sudoers.d/frp-manager-security-events
```

Only use that rule if `frpmanager` is the actual FRP Manager SSH account.
Restrict the account to its intended SSH keys and commands as appropriate.
Do not give a general `NOPASSWD: ALL` grant.

## LXC deployment

When the FRP Manager auto-updater deploys the commit containing
`app.py` and `sso_app.py`, authenticated Keycloak users can request:

`GET /api/security/events`

This endpoint executes only the fixed SSH command
`sudo -n /usr/local/sbin/frp-manager-security-events`, with strict host
key verification and a short timeout. Failed reads return HTTP 503,
not empty successful reports.

## Scope and retention

- Journal source: `frps.service` on OVH, up to 1500 entries from past 24 h.
- Classes: failed TLS, failed authentication, port rejection, proxy failures,
  FRPC client login/exit and proxy creation.
- Results: at most 200 aggregated events; duplicate categories/details within
  a 5-minute bucket increment `count`.
- Raw journal messages never leave the OVH exporter. Secret-containing text
  from unrecognized messages is discarded. FRPC source addresses may be
  present in sanitized `client_login` event details.
- Events are read on demand, without storing a duplicate long-term database.
  Actual history lifetime depends on OVH's persistent journal retention.
- These logs are **not** an exhaustive player connection history or traffic
  analysis. FRPS logging cannot identify application-layer actions.

## Validation

On LXC: `python3 -m unittest discover -s tests -v`.

On OVH: execute exporter as root and inspect its JSON.

From LXC, test the existing SSH identity (do not show private key):

```sh
sudo -u frpmanager-svc ssh -i /etc/frp-manager/id_ed25519 \
  -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/etc/frp-manager/ssh/known_hosts \
  frpmanager@57.131.164.152 \
  'sudo -n /usr/local/sbin/frp-manager-security-events'
```

If the SSH account or host differs, use the existing values in
`FRPS_SSH_USER`/`FRPS_PUBLIC_HOST` rather than the example.
Avoid posting raw logs, tokens or SSH private keys.

## Control Center UI (October 2026)

The lightweight dashboard uses vanilla HTML/CSS/JavaScript. Live tunnel status
is polled every 15 seconds while visible, health history every 30 seconds, and
OVH events at most every 90 seconds. Security fetching runs in a worker thread,
so a slow SSH connection does not block other web requests.

Security Events uses **client-side** time filters (1/6/12/24 hours), severity
and search filters, 20/50/100-row pagination and incident detail. The source
remains limited to the latest 24 hours and at most 200 event groups; pagination
does not imply unlimited historical storage. Individual player actions or UDP
payloads are not captured.

The OVH exporter must be updated independently: the LXC application auto-update
does **not** install anything on the VPS. To recognize FRPC token mismatch,
the exporter must include the `authentication_failed` pattern for
`token login doesn't match token configuration`. The known October 10
unknown client's token authentication was rejected; an observed login-info
record alone is not successful authentication.

For Health, durations are based on first observed transitions and are labeled
as observation windows, not guaranteed service uptime. Stale collector
snapshots are displayed as unknown rather than falsely healthy.
