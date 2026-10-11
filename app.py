#!/usr/bin/env python3

import base64
import json
import os
import subprocess
import tomllib
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

FRPC_CONFIG = Path(os.getenv("FRPC_CONFIG", "/etc/frp/frpc.toml"))
OVH_HOST = os.getenv("FRPS_PUBLIC_HOST", "")
OVH_USER = os.getenv("FRPS_SSH_USER", "frpmanager")
SSH_KEY = os.getenv("FRPS_SSH_KEY", "/etc/frp-manager/id_ed25519")


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def command(*args, timeout=10):
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Command failed"
        )
    return result.stdout.strip()


def read_config():
    with FRPC_CONFIG.open("rb") as f:
        return tomllib.load(f)


def get_frpc_status(config):
    web = config["webServer"]

    host = web.get("addr", "127.0.0.1")
    port = web.get("port", 7400)
    user = web.get("user", "")
    password = web.get("password", "")

    # Authentication data stays inside the backend.
    credentials = base64.b64encode(
        f"{user}:{password}".encode()
    ).decode()

    request = urllib.request.Request(
        f"http://{host}:{port}/api/status",
        headers={
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
        }
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        data = json.load(response)

    if not isinstance(data, dict):
        raise ValueError("Unexpected FRP status response")

    statuses = {}

    for protocol, entries in data.items():
        if not isinstance(entries, list):
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            name = entry.get("name")

            if name:
                statuses[(protocol.lower(), name)] = {
                    "status": entry.get("status", "unknown"),
                    "error": entry.get("err") or None,
                }

    return statuses


def get_tunnels():
    config = read_config()

    service = command("systemctl", "is-active", "frpc")
    status_error = None

    try:
        statuses = get_frpc_status(config)
        monitoring = "available"
    except Exception:
        statuses = {}
        monitoring = "unavailable"
        status_error = "Unable to retrieve FRP API status"

    tunnels = []

    for proxy in config.get("proxies", []):
        protocol = str(proxy.get("type", "")).lower()
        name = proxy.get("name", "")

        live = statuses.get((protocol, name))

        if live:
            state = live["status"]
            error = live["error"]
        else:
            state = "unknown"
            error = None

        tunnels.append({
            "name": name,
            "protocol": protocol,
            "local_ip": proxy.get("localIP"),
            "local_port": proxy.get("localPort"),
            "public_ip": OVH_HOST,
            "public_port": proxy.get("remotePort"),
            "status": state,
            "error": error,
            "status_source": (
                "frpc_api" if live else "unavailable"
            ),
        })

    active = sum(
        1 for tunnel in tunnels
        if str(tunnel["status"]).lower() == "running"
    )

    return {
        "timestamp": timestamp(),
        "client_service": service,
        "monitoring": monitoring,
        "monitoring_error": status_error,
        "total": len(tunnels),
        "active": active if monitoring == "available" else None,
        "tunnels": tunnels,
    }


def get_ovh():
    output = command(
        "ssh",
        "-i", SSH_KEY,
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + os.getenv(
            "FRPS_SSH_KNOWN_HOSTS", "/etc/frp-manager/ssh/known_hosts"
        ),
        "-o", "ConnectTimeout=5",
        f"{OVH_USER}@{OVH_HOST}",
        os.getenv("FRPS_STATUS_COMMAND", "sudo -n /usr/local/sbin/frp-manager-ovh status"),
        timeout=12,
    )

    data = json.loads(output)
    data["timestamp"] = timestamp()
    return data


def get_frps_security():
    """Read sanitized OVH FRPS hardening checks using pinned SSH."""
    output=command(
        "ssh","-i",SSH_KEY,"-o","IdentitiesOnly=yes",
        "-o","BatchMode=yes","-o","StrictHostKeyChecking=yes",
        "-o","UserKnownHostsFile="+os.getenv("FRPS_SSH_KNOWN_HOSTS",
              "/etc/frp-manager/ssh/known_hosts"),
        "-o","ConnectTimeout=5",f"{OVH_USER}@{OVH_HOST}",
        "sudo -n /usr/local/sbin/frp-manager-security-check",timeout=12)
    if len(output)>20000:
        raise ValueError("Oversized OVH security report")
    data=json.loads(output)
    if not isinstance(data,dict) or not isinstance(data.get("checks"),list):
        raise ValueError("Invalid OVH security report")
    return data


def get_frps_metrics():
    """Limited read-only server metrics via fixed audited SSH command."""
    if not OVH_HOST:
        raise RuntimeError("FRPS host not configured")
    output=command(
        "ssh", "-i", SSH_KEY, "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile="+os.getenv("FRPS_SSH_KNOWN_HOSTS",
              "/etc/frp-manager/ssh/known_hosts"),
        "-o", "ConnectTimeout=5",
        f"{OVH_USER}@{OVH_HOST}",
        "sudo -n /usr/local/sbin/frp-manager-metrics",
        timeout=12)
    if len(output)>50000:
        raise ValueError("Metrics response exceeded limit")
    data=json.loads(output)
    if type(data) is not dict or type(data.get("available")) is not bool or type(data.get("proxies")) is not list:
        raise ValueError("Invalid remote metrics response")
    return data


def get_security_events():
    if not OVH_HOST:
        raise RuntimeError("FRPS SSH host is not configured")
    output = command(
        "ssh", "-i", SSH_KEY, "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + os.getenv(
            "FRPS_SSH_KNOWN_HOSTS", "/etc/frp-manager/ssh/known_hosts"),
        "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5",
        f"{OVH_USER}@{OVH_HOST}",
        "sudo -n /usr/local/sbin/frp-manager-security-events",
        timeout=24,
    )
    if len(output) > 256000:
        raise ValueError("Oversized security event response")
    data=json.loads(output)
    if not isinstance(data,dict) or not isinstance(data.get("events"),list):
        raise ValueError("Invalid security event response")
    return data


class Handler(BaseHTTPRequestHandler):

    def respond(self, code, data):
        payload = json.dumps(
            data,
            ensure_ascii=False,
            indent=2
        ).encode("utf-8")

        self.send_response(code)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8"
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urlsplit(self.path).path

        try:
            if path == "/api/health":
                self.respond(200, {
                    "application": "FRP Manager",
                    "mode": "read-only",
                    "status": "running",
                    "timestamp": timestamp()
                })

            elif path == "/api/tunnels":
                self.respond(200, get_tunnels())

            elif path == "/api/ovh":
                self.respond(200, get_ovh())

            elif path == "/api/integrations/homepage":
                data = get_tunnels()
                if data["active"] is None:
                    self.respond(503, {
                        "error": "Monitoring unavailable"
                    })
                else:
                    self.respond(200, {
                        "active": data["active"],
                        "total": data["total"]
                    })

            else:
                self.respond(404, {
                    "error": "Endpoint not found"
                })

        except Exception:
            self.respond(503, {
                "error": "Unable to retrieve data",
                "timestamp": timestamp()
            })

    def do_POST(self):
        self.respond(405, {
            "error": "Write operations are disabled"
        })

    def log_message(self, format, *args):
        print(
            f"{self.client_address[0]} {format % args}",
            flush=True
        )


if __name__ == "__main__":
    server = ThreadingHTTPServer(
        ("127.0.0.1", 8088),
        Handler
    )
    print(
        "FRP Manager API listening on 127.0.0.1:8088",
        flush=True
    )
    server.serve_forever()
