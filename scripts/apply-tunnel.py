#!/usr/bin/env python3
"""Root-owned, narrowly scoped one-request FRPC tunnel creation worker.

Only accepts strictly validated JSON, never executes user-provided commands.
Requires an explicit root-created enable marker before processing requests.
"""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tomllib

STATE = Path("/var/lib/frp-manager")
SOURCE = Path("/etc/frp/frpc.toml")
REQUEST = STATE / "tunnel-create-request.json"
STATUS = STATE / "tunnel-create-status.json"
ENABLED = Path("/etc/frp-manager/tunnel-writes-enabled")
BACKUPS = Path("/var/backups/frp-manager/tunnels")


def atomic_status(value):
    with tempfile.NamedTemporaryFile(mode="w", dir=STATE, prefix=".tunnel-status-",
                                     delete=False) as handle:
        temp = Path(handle.name)
        json.dump(value, handle)
        handle.write("\n")
    os.chmod(temp, 0o644)
    os.replace(temp, STATUS)


def run(cmd, timeout=25):
    return subprocess.run(cmd, check=True, timeout=timeout, capture_output=True, text=True)


def validate(value, existing):
    if type(value) is not dict or set(value) != {"name", "protocol", "local_ip", "local_port", "public_port"}:
        raise ValueError("Invalid request fields")
    name = value["name"]
    proto = value["protocol"]
    host = value["local_ip"]
    local = value["local_port"]
    remote = value["public_port"]
    if type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
        raise ValueError("Invalid tunnel name")
    if proto not in ("tcp", "udp"):
        raise ValueError("Invalid protocol")
    if type(host) is not str:
        raise ValueError("Invalid target")
    try:
        addr = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as exc:
        raise ValueError("Invalid target") from exc
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved or addr.is_loopback:
        raise ValueError("Invalid target")
    if type(local) is not int or type(remote) is not int or not 1 <= local <= 65535 or not 1 <= remote <= 65535:
        raise ValueError("Invalid port")
    proxies = existing.get("proxies", [])
    if type(proxies) is not list:
        raise ValueError("Invalid proxies list")
    for proxy in proxies:
        if type(proxy) is not dict:
            raise ValueError("Invalid proxy")
        if str(proxy.get("name", "")).lower() == name.lower():
            raise ValueError("Name already exists")
        if str(proxy.get("type", "")).lower() == proto and proxy.get("remotePort") == remote:
            raise ValueError("Remote port already used for protocol")
    return name, proto, str(addr), local, remote


def worker():
    if not REQUEST.is_file():
        return
    with open("/run/lock/frp-manager-tunnel.lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not REQUEST.is_file():
            return
        # Never treat an untrusted symlink as a request.
        if REQUEST.is_symlink():
            REQUEST.unlink(missing_ok=True)
            raise ValueError("Symlink request rejected")
        request = REQUEST.read_bytes()
        REQUEST.unlink(missing_ok=True)
        record = {"state": "failed", "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        backup = None
        changed = False
        try:
            if not ENABLED.is_file() or ENABLED.is_symlink() or ENABLED.stat().st_uid != 0:
                raise ValueError("Tunnel writes are disabled")
            if len(request) > 4096:
                raise ValueError("Request too large")
            data = json.loads(request)
            if type(data) is not dict or set(data) != {"tunnel"}:
                raise ValueError("Invalid envelope")
            with SOURCE.open("rb") as source:
                current = tomllib.load(source)
            name, proto, host, local, remote = validate(data["tunnel"], current)
            # Preserve tokens, comments and all existing proxy settings exactly.
            original = SOURCE.read_bytes()
            suffix = ("\n[[proxies]]\n"
                      f"name = {json.dumps(name)}\n"
                      f"type = {json.dumps(proto)}\n"
                      f"localIP = {json.dumps(host)}\n"
                      f"localPort = {local}\n"
                      f"remotePort = {remote}\n").encode()
            candidate = original + (b"\n" if not original.endswith(b"\n") else b"") + suffix
            with tempfile.NamedTemporaryFile(mode="wb", dir=SOURCE.parent,
                                             prefix=".frpc-candidate-", delete=False) as handle:
                temp = Path(handle.name)
                handle.write(candidate)
            try:
                os.chmod(temp, SOURCE.stat().st_mode & 0o777)
                run(["/usr/local/bin/frpc", "verify", "-c", str(temp)], timeout=15)
                BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
                stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
                backup = BACKUPS / (stamp + "-" + name + ".toml")
                shutil.copy2(SOURCE, backup)
                os.chmod(backup, 0o600)
                os.replace(temp, SOURCE)
                changed = True
                run(["systemctl", "restart", "frpc"], timeout=30)
                run(["systemctl", "is-active", "--quiet", "frpc"], timeout=10)
                # Confirm target proxy registered with FRPC after restart.
                with SOURCE.open("rb") as check_file:
                    verified = tomllib.load(check_file)
                if not any(p.get("name") == name and p.get("type") == proto for p in verified.get("proxies", [])):
                    raise ValueError("Tunnel missing after restart")
                record = {"state": "success", "name": name, "protocol": proto,
                          "backup": str(backup), "updated_at": record["updated_at"]}
            finally:
                temp.unlink(missing_ok=True)
        except Exception as exc:
            if changed and backup:
                shutil.copy2(backup, SOURCE)
                try:
                    run(["systemctl", "restart", "frpc"], timeout=30)
                except Exception:
                    record["rollback_failed"] = True
            record["error"] = str(exc)[:200]
        atomic_status(record)
        if record["state"] != "success":
            raise SystemExit(1)


if __name__ == "__main__":
    worker()
