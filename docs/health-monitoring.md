# Health, connectivity history and security audit

FRPC health monitoring is read-only. The collector polls the authenticated
local FRPC `/api/status` every 30 seconds through a sandboxed systemd
timer and retains **state transitions**, never every sample or every packet.

**Connections and security:**
- A `running` FRPC proxy is evidence that the proxy was accepted by FRPS,
  not proof of end-to-end application reachability.
- An unavailable FRPC API means `unknown`, **not** `disconnected`.
- No fabricated ping, packet counts, availability percentages or application
  health checks. UDP in particular requires a protocol-specific handshake.
- The collector does **not** inspect network payloads or identify individual
  players. It does not detect abuse inside tunneled traffic.
- `/api/health/overview`, `/api/health/tunnels`,
  `/api/health/history`, `/api/health/metrics` require a valid Keycloak
  session and an FRP Manager client role.
- SQLite `/var/lib/frp-manager/health.db` (root-only, 0600) stores up to
  10,000 transitions. A sanitized JSON snapshot of the latest 200 is exposed
  to the web service as `/var/lib/frp-manager/health-public.json`.
- Both update and tunnel history audit already record administrative actions.
  Keycloak authentication events require Keycloak server audit retention.
  Actual remote-client source addresses and traffic volume need FRPS-side
  logging / firewall flow logs and an explicit privacy and retention policy.
  FRPC `journald` may include connection/error records, but is not a
  trustworthy complete per-client security audit.

## Deployment to Debian 13 FRPC LXC

Run as root **after pulling the repo**, with no queued writes:

```bash
python3 -m py_compile scripts/health-collector.py sso_app.py
python3 -m unittest discover -s tests -v
install -o root -g root -m 0755 scripts/health-collector.py /usr/local/sbin/frp-manager-health-collector
install -o root -g root -m 0644 deploy/frp-manager-health.service /etc/systemd/system/frp-manager-health.service
install -o root -g root -m 0644 deploy/frp-manager-health.timer /etc/systemd/system/frp-manager-health.timer
systemctl daemon-reload
systemctl enable --now frp-manager-health.timer
systemctl start frp-manager-health.service
systemctl status frp-manager-health.service --no-pager
cat /var/lib/frp-manager/health-public.json
```

The web application is updated independently by the existing auto-updater.
Verify the deployed Git revision before invoking the new APIs. No new tunnel
writes or FRPC restarts are required.

To inspect the retained transitions read-only:
```bash
sqlite3 -readonly /var/lib/frp-manager/health.db 'SELECT recorded_at,subject,previous,current,reason FROM health_events ORDER BY id DESC LIMIT 20;'
```

Do not enable verbose traffic or packet dumps by default. Prefer log
rotation/retention for journald and FRPS logs and collect source IP metadata
only when you have a concrete operational or abuse-investigation need.
