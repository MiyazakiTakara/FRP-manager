#!/usr/bin/env python3
"""Optional failed-authentication burst alerts using sanitized FRPS events.

Does not inspect packet content or claim that a failed login succeeded.
Relies on an installed restricted SSH FRPS security-event exporter.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

STATE=Path(os.environ.get("FRP_AUTH_ALERT_STATE","/var/lib/frp-manager/auth-alert-state.json"))
HOST_RE=re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,251}\Z")

def retrieve(host,key,known):
    if not HOST_RE.fullmatch(host) or host.startswith("-"):
        raise ValueError("Invalid OVH hostname")
    result=subprocess.run(["ssh","-i",key,"-o","IdentitiesOnly=yes","-o","BatchMode=yes",
        "-o","StrictHostKeyChecking=yes","-o","UserKnownHostsFile="+known,
        "-o","ConnectTimeout=5","frpmanager@"+host,
        "sudo -n /usr/local/sbin/frp-manager-security-events"],
        capture_output=True,text=True,timeout=18,check=True)
    if len(result.stdout)>256000:
        raise ValueError("Security feed too large")
    data=json.loads(result.stdout)
    if type(data) is not dict or type(data.get("events")) is not list:
        raise ValueError("Invalid security feed")
    return data["events"][:200]

def summarize(events,now=None,minutes=15):
    now=now or datetime.now(timezone.utc)
    cutoff=now-timedelta(minutes=minutes)
    total=0
    latest=None
    for event in events:
        if not isinstance(event,dict) or event.get("category")!="authentication_failed":
            continue
        try:
            stamp=datetime.fromisoformat(event["timestamp"].replace("Z","+00:00"))
            count=event["count"]
            if stamp.tzinfo is None or not isinstance(count,int) or not 0<count<=2000:
                continue
            if stamp>=cutoff and stamp<=now+timedelta(seconds=30):
                total+=count
                latest=max(latest or stamp,stamp)
        except (ValueError,TypeError,KeyError):
            continue
    return {"count":total,"latest":latest.isoformat(timespec="seconds") if latest else None}

def notify(webhook,count):
    content=("FRP Manager SECURITY: "+str(count)+" failed FRPS authentication attempts "
             "aggregated in the last 15 minutes. Review Security Events; do not assume compromise.")
    body=json.dumps({"content":content}).encode()
    req=urllib.request.Request(webhook,data=body,
        headers={"Content-Type":"application/json","User-Agent":"FRP-Manager-AuthAlerts/1"},method="POST")
    with urllib.request.urlopen(req,timeout=8) as response:
        if response.status not in (200,204):
            raise RuntimeError("Webhook delivery rejected")

def persist(record):
    STATE.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=".auth-alert-",dir=str(STATE.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as stream:
            json.dump(record,stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp,0o600)
        os.replace(tmp,STATE)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def run():
    webhook=os.environ.get("FRP_ALERT_WEBHOOK_URL","")
    host=os.environ.get("FRP_ALERT_OVH_HOST","")
    if not webhook or not host:
        return
    if not webhook.startswith("https://") or len(webhook)>1024:
        raise ValueError("Invalid webhook")
    key=os.environ.get("FRP_ALERT_SSH_KEY","/etc/frp-manager/id_ed25519.svc")
    known=os.environ.get("FRP_ALERT_KNOWN_HOSTS","/etc/frp-manager/ssh/known_hosts")
    observation=summarize(retrieve(host,key,known))
    try:
        previous=json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError,ValueError):
        previous=None
    # First call establishes a baseline; no notification for historical events.
    if previous is None:
        persist(observation)
        return
    if observation["count"]>=3 and observation["latest"]!=previous.get("latest"):
        notify(webhook,observation["count"])
    persist(observation)

if __name__=="__main__":
    run()
