#!/usr/bin/env python3
"""Root-owned, narrowly scoped one-request FRPC tunnel creation worker.

Only accepts strictly validated JSON, never executes user-provided commands.
Requires an explicit root-created enable marker before processing requests.
"""
import fcntl
import base64
import urllib.request
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
import hashlib

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


def status_map(config):
    web = config.get("webServer")
    if not isinstance(web, dict):
        raise ValueError("Missing FRPC API configuration")
    host = web.get("addr", "127.0.0.1")
    port = web.get("port", 7400)
    user = web.get("user", "")
    password = web.get("password", "")
    auth = base64.b64encode((str(user) + ":" + str(password)).encode()).decode()
    url = "http://" + str(host) + ":" + str(port) + "/api/status"
    request = urllib.request.Request(url, headers={"Authorization": "Basic " + auth})
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.load(response)
    if type(payload) is not dict:
        raise ValueError("Invalid FRPC status")
    result = {}
    for protocol, entries in payload.items():
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and entry.get("name"):
                    result[(protocol.lower(), entry["name"])] = entry.get("status", "").lower()
    return result


def proxy_blocks(original):
    # Preserve all unrelated TOML including comments and secrets.
    text = original.decode("utf-8")
    marker = re.compile(r"(?m)^\s*\[\[proxies\]\]\s*(?:#.*)?$")
    matches = list(marker.finditer(text))
    if not matches:
        return text, []
    blocks = []
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[match.start():end]
        parsed = tomllib.loads(block)
        if len(parsed.get("proxies", [])) != 1:
            raise ValueError("Unsupported proxy block format")
        blocks.append((match.start(), end, parsed["proxies"][0], block))
    return text, blocks


def apply_operation(original, data, current):
    # Only supported basic TCP/UDP proxy blocks may be edited or deleted.
    action = data.get("action", "create")
    if action not in ("create", "edit", "delete"):
        raise ValueError("Unknown action")
    text, blocks = proxy_blocks(original)
    if action == "create":
        if set(data) != {"tunnel"} and set(data) != {"action", "tunnel"}:
            raise ValueError("Invalid create request")
        name, proto, host, local, remote = validate(data["tunnel"], current)
        candidate = text.rstrip("\n") + "\n\n[[proxies]]\n" + (
            f"name = {json.dumps(name)}\ntype = {json.dumps(proto)}\n"
            f"localIP = {json.dumps(host)}\nlocalPort = {local}\nremotePort = {remote}\n"
        )
        return candidate.encode(), name, proto, action

    if set(data) != ({"action", "name", "tunnel"} if action == "edit" else {"action", "name"}):
        raise ValueError("Invalid operation fields")
    name = data["name"]
    if type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
        raise ValueError("Invalid tunnel name")
    selected = [(start, end, p, block) for start, end, p, block in blocks if p.get("name") == name]
    if len(selected) != 1:
        raise ValueError("Tunnel not uniquely found")
    start, end, existing, block = selected[0]
    proto = str(existing.get("type", "")).lower()
    if proto not in ("tcp", "udp"):
        raise ValueError("Unsupported tunnel type")
    # Do not silently destroy advanced proxy configuration.
    if set(existing) - {"name", "type", "localIP", "localPort", "remotePort"}:
        raise ValueError("Advanced proxy configuration cannot be edited or deleted in this version")
    if action == "delete":
        return (text[:start] + text[end:]).encode(), name, proto, action

    target = data["tunnel"]
    if type(target) is not dict or target.get("name") != name or target.get("protocol") != proto:
        raise ValueError("Name and protocol cannot change")
    without = {"proxies": [p for p in current.get("proxies", []) if p.get("name") != name]}
    _, _, host, local, remote = validate(target, without)
    # Preserve the block heading/comments; replace only supported keys.
    replacements = {"localIP": json.dumps(host), "localPort": str(local), "remotePort": str(remote)}
    for field, value in replacements.items():
        pattern = re.compile(r"(?m)^(\s*" + field + r"\s*=\s*)([^#\r\n]*)(.*)$")
        if len(pattern.findall(block)) != 1:
            raise ValueError("Ambiguous proxy configuration field " + field)
        block = pattern.sub(lambda match: match.group(1) + value + match.group(3), block)
    return (text[:start] + block + text[end:]).encode(), name, proto, action


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
            if type(data) is not dict:
                raise ValueError("Invalid envelope")
            with SOURCE.open("rb") as source:
                current = tomllib.load(source)
            original = SOURCE.read_bytes()
            candidate, name, proto, action = apply_operation(original, data, current)
            if candidate == original:
                raise ValueError("No changes to apply")
            previous_status = status_map(current)
            prior_running = {
                (str(p.get("type", "")).lower(), p.get("name"))
                for p in current.get("proxies", [])
                if previous_status.get((str(p.get("type", "")).lower(), p.get("name"))) == "running"
                and not (action == "delete" and p.get("name") == name)
            }
            with tempfile.NamedTemporaryFile(mode="wb", dir=SOURCE.parent,
                                             prefix=".frpc-candidate-", delete=False) as handle:
                temp = Path(handle.name)
                handle.write(candidate)
            try:
                shutil.copystat(SOURCE, temp)
                os.chmod(temp, SOURCE.stat().st_mode & 0o777)
                frpc_bin = next((str(p) for p in (Path("/usr/local/bin/frpc"), Path("/usr/bin/frpc"))
                                 if p.is_file() and os.access(p, os.X_OK)), None)
                if frpc_bin is None:
                    raise ValueError("FRPC executable not found")
                run([frpc_bin, "verify", "-c", str(temp)], timeout=15)
                BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
                stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
                backup = BACKUPS / (stamp + "-" + name + ".toml")
                shutil.copy2(SOURCE, backup)
                os.chmod(backup, 0o600)
                os.replace(temp, SOURCE)
                changed = True
                # Verify the dashboard can still read the configuration.
                run(["runuser", "-u", "frpmanager-svc", "--", "test", "-r", str(SOURCE)], timeout=5)
                run(["systemctl", "restart", "frpc"], timeout=30)
                run(["systemctl", "is-active", "--quiet", "frpc"], timeout=10)
                # New proxy and all previously running proxies must remain healthy.
                deadline = time.monotonic() + 20
                while True:
                    try:
                        statuses = status_map(current)
                        expected = statuses.get((proto, name)) == "running" if action != "delete" else (proto, name) not in statuses
                        if expected and all(
                            statuses.get(key) == "running" for key in prior_running
                        ):
                            break
                    except Exception:
                        pass
                    if time.monotonic() >= deadline:
                        raise ValueError("FRPC proxy health check failed")
                    time.sleep(1)
                record = {"state": "success", "name": name, "protocol": proto, "action": action,
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
