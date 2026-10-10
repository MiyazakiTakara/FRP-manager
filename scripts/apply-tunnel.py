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
import sqlite3
import sys
from datetime import datetime, timezone

STATE = Path("/var/lib/frp-manager")
SOURCE = Path("/etc/frp/frpc.toml")
REQUEST = STATE / "tunnel-create-request.json"
STATUS = STATE / "tunnel-create-status.json"
ENABLED = Path("/etc/frp-manager/tunnel-writes-enabled")
BACKUPS = Path("/var/backups/frp-manager/tunnels")
MANAGE_ENABLED = Path("/etc/frp-manager/tunnel-manage-enabled")
HISTORY_DB = STATE / "history.db"
HISTORY_PUBLIC = STATE / "history-public.json"
PORT_POLICY = Path("/etc/frp-manager/allowed-ports.json")
RESTORE_ENABLED = Path("/etc/frp-manager/tunnel-restore-enabled")


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


def check_port_policy(protocol, public_port):
    """Optional local mirror of FRPS allowPorts (not firewall verification)."""
    if not PORT_POLICY.exists():
        return
    if PORT_POLICY.is_symlink():
        raise ValueError("Port policy must not be a symlink")
    try:
        policy = json.loads(PORT_POLICY.read_text(encoding="utf-8"))
        if (type(policy) is not dict or set(policy) != {"tcp", "udp"}
                or any(type(policy[k]) is not list for k in ("tcp", "udp"))):
            raise ValueError("Invalid port policy structure")
        allowed = False
        for entry in policy[protocol]:
            if (type(entry) is not list or len(entry) != 2
                    or any(type(n) is not int or not 1 <= n <= 65535 for n in entry)
                    or entry[0] > entry[1]):
                raise ValueError("Invalid port range")
            if entry[0] <= public_port <= entry[1]:
                allowed = True
        if not allowed:
            raise ValueError("Port {} / {} is not allowed by configured FRPS policy".format(public_port, protocol.upper()))
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        raise ValueError("Unable to validate FRPS port policy") from exc


def status_details(config):
    web = config.get("webServer")
    if not isinstance(web, dict):
        raise ValueError("Missing FRPC API configuration")
    host = web.get("addr", "127.0.0.1")
    port = web.get("port", 7400)
    user = web.get("user", "")
    password = web.get("password", "")
    auth = base64.b64encode((str(user) + ":" + str(password)).encode()).decode()
    url = "http://" + str(host) + ":" + str(port) + "/api/status"
    req = urllib.request.Request(url, headers={"Authorization": "Basic " + auth})
    with urllib.request.urlopen(req, timeout=5) as response:
        payload = json.load(response)
    if type(payload) is not dict:
        raise ValueError("Invalid FRPC status")
    details = {}
    for protocol, entries in payload.items():
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict) and entry.get("name"):
                    details[(protocol.lower(), entry["name"])] = entry
    return details


def status_map(config):
    return {key: str(value.get("status", "")).lower()
            for key, value in status_details(config).items()}


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



def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def public_proxies(blob):
    config = tomllib.loads(blob.decode("utf-8"))
    result = []
    for entry in config.get("proxies", []):
        if not isinstance(entry, dict):
            continue
        result.append({k: entry.get(source) for k, source in (
            ("name", "name"), ("protocol", "type"), ("local_ip", "localIP"),
            ("local_port", "localPort"), ("public_port", "remotePort"))})
    return result


def history_connection():
    STATE.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(HISTORY_DB, timeout=15)
    os.chmod(HISTORY_DB, 0o600)
    connection.execute("PRAGMA busy_timeout=15000")
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("""CREATE TABLE IF NOT EXISTS versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recorded_at TEXT NOT NULL,
        action TEXT NOT NULL,
        tunnel TEXT,
        actor TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        config BLOB NOT NULL,
        summary TEXT NOT NULL
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS operation_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recorded_at TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        tunnel TEXT,
        outcome TEXT NOT NULL,
        error TEXT,
        rollback_failed INTEGER NOT NULL DEFAULT 0
    )""")
    connection.commit()
    return connection


def record_operation_event(connection, actor, action, tunnel, outcome, error=None, rollback_failed=False):
    connection.execute(
        "INSERT INTO operation_events(recorded_at,actor,action,tunnel,outcome,error,rollback_failed) "
        "VALUES(?,?,?,?,?,?,?)",
        (utc_now(), actor, action, tunnel, outcome, error, int(rollback_failed)))
    connection.commit()


def export_operation_events(connection):
    rows = connection.execute(
        "SELECT id,recorded_at,actor,action,tunnel,outcome,error,rollback_failed "
        "FROM operation_events ORDER BY id DESC LIMIT 100").fetchall()
    return [{"id": r[0], "recorded_at":r[1], "actor":r[2], "action":r[3],
             "tunnel":r[4], "outcome":r[5], "error":r[6],
             "rollback_failed":bool(r[7])} for r in rows]


def ensure_baseline(connection, current_blob):
    row = connection.execute("SELECT id FROM versions ORDER BY id DESC LIMIT 1").fetchone()
    if row:
        # Do not silently attribute externally modified configuration to a panel action.
        latest = connection.execute("SELECT sha256 FROM versions ORDER BY id DESC LIMIT 1").fetchone()[0]
        if latest != hashlib.sha256(current_blob).hexdigest():
            raise ValueError("Live configuration differs from last history snapshot; manual reconciliation required")
        return
    connection.execute(
        "INSERT INTO versions(recorded_at, action, tunnel, actor, sha256, config, summary) VALUES(?,?,?,?,?,?,?)",
        (utc_now(), "baseline", None, "system", hashlib.sha256(current_blob).hexdigest(),
         current_blob, "Initial configuration snapshot"))
    connection.commit()


def publish_history(connection):
    rows = connection.execute(
        "SELECT id, recorded_at, action, tunnel, actor, sha256, summary, config "
        "FROM versions ORDER BY id DESC LIMIT 100").fetchall()
    result = []
    older = {}
    chronological = list(reversed(rows))
    for version, at, action, tunnel, actor, digest, summary, config in chronological:
        safe = public_proxies(config)
        old_index = {p["name"]: p for p in older.get("proxies", []) if p.get("name")}
        new_index = {p["name"]: p for p in safe if p.get("name")}
        changes = []
        for name in sorted(set(old_index) | set(new_index)):
            before = old_index.get(name)
            after = new_index.get(name)
            if before != after:
                changes.append({"name": name, "before": before, "after": after})
        result.append({"id": version, "recorded_at": at, "action": action,
                       "tunnel": tunnel, "actor": actor, "sha256": digest,
                       "summary": summary, "changes": changes})
        older = {"proxies": safe}
    payload = {"versions": list(reversed(result)), "latest_version": result[-1]["id"] if result else None,
               "operations": export_operation_events(connection)}
    with tempfile.NamedTemporaryFile(mode="w", dir=STATE, prefix=".history-public-", delete=False) as handle:
        path = Path(handle.name)
        json.dump(payload, handle, separators=(",", ":"))
        handle.write("\n")
    os.chmod(path, 0o644)
    os.replace(path, HISTORY_PUBLIC)


def history_initialize():
    with open("/run/lock/frp-manager-tunnel.lock", "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with history_connection() as connection:
            ensure_baseline(connection, SOURCE.read_bytes())
            publish_history(connection)
    print("FRP history initialized. Public metadata: " + str(HISTORY_PUBLIC))


def history_record(connection, candidate, action, name, actor):
    connection.execute(
        "INSERT INTO versions(recorded_at,action,tunnel,actor,sha256,config,summary) "
        "VALUES(?,?,?,?,?,?,?)",
        (utc_now(), action, name, actor, hashlib.sha256(candidate).hexdigest(),
         candidate, action.capitalize() + " tunnel " + name))
    connection.commit()
    publish_history(connection)


def history_verify():
    if not HISTORY_DB.is_file():
        raise ValueError("History database missing")
    connection = sqlite3.connect("file:" + str(HISTORY_DB) + "?mode=ro", uri=True)
    try:
        rows = connection.execute("SELECT id,sha256,config FROM versions ORDER BY id").fetchall()
        if not rows:
            raise ValueError("History database contains no snapshots")
        for version, digest, config in rows:
            if hashlib.sha256(config).hexdigest() != digest:
                raise ValueError("Snapshot integrity mismatch at v" + str(version))
        live = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        if rows[-1][1] != live:
            raise ValueError("Live FRPC configuration differs from v" + str(rows[-1][0]))
        print("HISTORY OK: " + str(len(rows)) + " versions; live config matches v" + str(rows[-1][0]))
    finally:
        connection.close()


def history_backup():
    if not HISTORY_DB.is_file():
        raise ValueError("History database missing")
    destination = Path("/var/backups/frp-manager/history")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = destination / ("history-" + stamp + ".db")
    source = sqlite3.connect("file:" + str(HISTORY_DB) + "?mode=ro", uri=True)
    target = sqlite3.connect(path)
    try:
        os.chmod(path, 0o600)
        source.backup(target)
        row = target.execute("PRAGMA integrity_check").fetchone()
        if not row or row[0] != "ok":
            raise ValueError("SQLite backup integrity check failed")
    finally:
        target.close()
        source.close()
    print("SQLite history backup created: " + str(path))


def restore_candidate(connection, data, original):
    if set(data) != {"action", "version", "expected_sha256"}:
        raise ValueError("Invalid restore request fields")
    version = data["version"]
    expected = data["expected_sha256"]
    if type(version) is not int or version < 1:
        raise ValueError("Invalid version")
    if type(expected) is not str or not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise ValueError("Invalid expected config hash")
    if hashlib.sha256(original).hexdigest() != expected:
        raise ValueError("Configuration changed since restore preview")
    row = connection.execute("SELECT config,sha256 FROM versions WHERE id=?", (version,)).fetchone()
    if row is None:
        raise ValueError("Version not found")
    target, digest = row
    if hashlib.sha256(target).hexdigest() != digest:
        raise ValueError("Snapshot integrity mismatch")
    if target == original:
        raise ValueError("Already running requested configuration")
    parsed = tomllib.loads(target.decode("utf-8"))
    if type(parsed.get("proxies", [])) is not list:
        raise ValueError("Invalid snapshot proxies")
    for proxy in parsed.get("proxies", []):
        if not isinstance(proxy, dict):
            raise ValueError("Invalid snapshot proxy")
        if proxy.get("type") in ("tcp", "udp") and type(proxy.get("remotePort")) is int:
            check_port_policy(proxy["type"], proxy["remotePort"])
    return target, "version-" + str(version), "restore", "restore"

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
        history = None
        original_mode = None
        actor = "unknown"
        action = "unknown"
        name = None
        try:
            if not ENABLED.is_file() or ENABLED.is_symlink() or ENABLED.stat().st_uid != 0:
                raise ValueError("Tunnel writes are disabled")
            if len(request) > 4096:
                raise ValueError("Request too large")
            data = json.loads(request)
            if type(data) is not dict:
                raise ValueError("Invalid envelope")
            actor_info = data.pop("actor", None)
            if actor_info is None:
                actor = "legacy-panel-admin"
            elif (type(actor_info) is dict
                  and set(actor_info) == {"sub", "name"}
                  and all(type(actor_info[k]) is str and 1 <= len(actor_info[k]) <= 256
                          for k in ("sub", "name"))):
                actor = actor_info["name"] + " [" + actor_info["sub"] + "]"
            else:
                raise ValueError("Invalid actor metadata")
            with SOURCE.open("rb") as source:
                current = tomllib.load(source)
            original = SOURCE.read_bytes()
            original_mode = SOURCE.stat().st_mode & 0o777
            history = history_connection()
            ensure_baseline(history, original)
            if data.get("action") == "restore":
                if not RESTORE_ENABLED.is_file() or RESTORE_ENABLED.is_symlink() or RESTORE_ENABLED.stat().st_uid != 0:
                    raise ValueError("Restore is not enabled by root")
                candidate, name, proto, action = restore_candidate(history, data, original)
            else:
                candidate, name, proto, action = apply_operation(original, data, current)
            if action in ("edit", "delete") and (not MANAGE_ENABLED.is_file() or MANAGE_ENABLED.is_symlink() or MANAGE_ENABLED.stat().st_uid != 0):
                raise ValueError("Edit/Delete operations are not enabled")
            record.update({"action": action, "name": name, "protocol": proto})
            if candidate == original:
                raise ValueError("No changes to apply")
            if action in ("create", "edit"):
                selected = next(p for p in tomllib.loads(candidate.decode("utf-8"))["proxies"] if p["name"] == name)
                check_port_policy(proto, selected["remotePort"])
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
                last_problem = None
                restored_proxies = set()
                if action == "restore":
                    restored_proxies = {(str(p.get("type", "")).lower(), p.get("name"))
                                       for p in tomllib.loads(candidate.decode("utf-8")).get("proxies", [])}
                while True:
                    try:
                        details = status_details(current)
                        statuses = {key: str(item.get("status", "")).lower() for key, item in details.items()}
                        detail = details.get((proto, name), {})
                        reason = str(detail.get("err", "") or detail.get("error", ""))[:160]
                        if reason:
                            # FRPC reports explicit server-side rejections in the status API.
                            # Fail immediately rather than waiting for the full health timeout.
                            last_problem = reason
                            if action != "delete" and "port not allowed" in reason.lower():
                                raise ValueError("FRPS rejected public port: port not allowed")
                        if action == "restore":
                            expected = all(statuses.get(key) == "running" for key in restored_proxies)
                        elif action == "delete":
                            expected = (proto, name) not in statuses
                        else:
                            expected = statuses.get((proto, name)) == "running"
                        if expected and all(
                            statuses.get(key) == "running" for key in prior_running
                        ):
                            break
                    except ValueError as exc:
                        if "FRPS rejected public port" in str(exc):
                            raise
                    except Exception:
                        pass
                    if time.monotonic() >= deadline:
                        raise ValueError("FRPC proxy health check failed" + (": " + last_problem if last_problem else ""))
                    time.sleep(1)
                history_record(history, candidate, action, name, actor)
                record_operation_event(history, actor, action, name, "success")
                publish_history(history)
                record = {"state": "success", "name": name, "protocol": proto, "action": action,
                          "backup": str(backup), "updated_at": record["updated_at"]}
            finally:
                temp.unlink(missing_ok=True)
        except Exception as exc:
            if changed and backup:
                try:
                    shutil.copy2(backup, SOURCE)
                    # Backup is intentionally 0600; restore the original ACL mask.
                    if original_mode is not None:
                        os.chmod(SOURCE, original_mode)
                    run(["runuser", "-u", "frpmanager-svc", "--", "test", "-r", str(SOURCE)], timeout=5)
                    run(["systemctl", "restart", "frpc"], timeout=30)
                    run(["systemctl", "is-active", "--quiet", "frpc"], timeout=10)
                except Exception:
                    record["rollback_failed"] = True
            record["error"] = str(exc)[:200]
            if history is not None:
                try:
                    record_operation_event(history, actor, action, name, "failed",
                                           record["error"], record.get("rollback_failed", False))
                    publish_history(history)
                except Exception:
                    pass
        if history is not None:
            history.close()
        atomic_status(record)
        if record["state"] != "success":
            raise SystemExit(1)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--init-history":
        history_initialize()
    elif len(sys.argv) == 2 and sys.argv[1] == "--verify-history":
        history_verify()
    elif len(sys.argv) == 2 and sys.argv[1] == "--backup-history":
        history_backup()
    elif len(sys.argv) == 1:
        worker()
    else:
        raise SystemExit("Unsupported arguments")
