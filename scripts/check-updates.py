#!/usr/bin/env python3
"""Poll a public GitHub branch and pre-download an update without installing it."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

STATE = Path("/var/lib/frp-manager")
CACHE = Path("/var/cache/frp-manager")
REPO = "https://github.com/MiyazakiTakara/FRP-manager.git"
BRANCH = "main"
FILES = ("app.py", "sso_app.py", "session_store.py", "update_web.py")
CONFIG = STATE / "update-settings.json"
RESULT = STATE / "update-check.json"
FAILURE = STATE / "update-auto-paused"
REVISION = STATE / "deployed-revision"
UPDATE_REQUEST = STATE / "update-request"


def read_json(path, default):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, ValueError):
        return default


def atomic_json(path, value):
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle)
            handle.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def run():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    CACHE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with Path("/run/lock/frp-manager-check.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        settings = read_json(CONFIG, {})
        interval = int(settings.get("interval_minutes", 30))
        if interval < 1 or interval > 1440:
            raise ValueError("Invalid polling interval")
        old = read_json(RESULT, {})
        now = int(time.time())
        if now - int(old.get("checked_epoch", 0)) < interval * 60:
            return

        installed = REVISION.read_text().strip() if REVISION.exists() else ""
        result = {
            "checked_epoch": now,
            "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "installed": installed,
            "latest": "",
            "state": "check-failed",
        }
        try:
            proc = subprocess.run(
                ["git", "ls-remote", REPO, "refs/heads/" + BRANCH],
                capture_output=True, text=True, timeout=25, check=True,
            )
            latest = proc.stdout.split()[0]
            if len(latest) != 40 or not all(c in "0123456789abcdef" for c in latest):
                raise ValueError("Invalid Git revision")
            result["latest"] = latest
            result["state"] = "up-to-date" if installed == latest else "update-available"
            if latest != installed and settings.get("auto_download", True):
                checkout = CACHE / latest
                if not checkout.exists():
                    with tempfile.TemporaryDirectory(dir=CACHE) as td:
                        target = Path(td) / "source"
                        subprocess.run(
                            ["git", "clone", "--quiet", "--depth", "1",
                             "--branch", BRANCH, REPO, str(target)],
                            check=True, timeout=90,
                        )
                        actual = subprocess.run(
                            ["git", "-C", str(target), "rev-parse", "HEAD"],
                            check=True, capture_output=True, text=True,
                        ).stdout.strip()
                        if actual == latest:
                            for name in FILES:
                                if not (target / name).is_file():
                                    raise ValueError("Incomplete source snapshot")
                            os.rename(target, checkout)
                result["downloaded"] = checkout.exists()
        except Exception:
            result["state"] = "check-failed"
            result["downloaded"] = False
        result["auto_install_paused"] = FAILURE.exists()
        atomic_json(RESULT, result)
        if (result["state"] == "update-available"
                and settings.get("auto_install", False)
                and result.get("downloaded", False)
                and not FAILURE.exists()):
            # The checker is sandboxed (ProtectSystem=strict). Only the
            # dedicated update service may modify /opt or create backups.
            # Queue atomically and ask systemd to start the service; do not
            # execute its installer in this restricted process.
            if UPDATE_REQUEST.exists():
                result["install_state"] = "already-queued"
            else:
                try:
                    fd = os.open(UPDATE_REQUEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    os.close(fd)
                    proc = subprocess.run(
                        ["systemctl", "start", "--no-block", "frp-manager-update.service"],
                        capture_output=True, text=True, timeout=10, check=False)
                    if proc.returncode != 0:
                        UPDATE_REQUEST.unlink(missing_ok=True)
                        result["install_state"] = "queue-failed"
                    else:
                        result["install_state"] = "queued"
                except (OSError, subprocess.TimeoutExpired):
                    UPDATE_REQUEST.unlink(missing_ok=True)
                    result["install_state"] = "queue-failed"
            atomic_json(RESULT, result)


if __name__ == "__main__":
    run()
