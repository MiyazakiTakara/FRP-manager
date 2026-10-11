#!/usr/bin/env python3
"""Opt-in FRP alert worker. Read-only collector source; no tunnel modifications.

On the first invocation a baseline is stored without notification.
Only changes to actionable unhealthy states cause a notification.
Configured webhook URL is a secret read from systemd EnvironmentFile.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import urllib.request

SOURCE = Path(os.environ.get("FRP_ALERT_SOURCE", "/var/lib/frp-manager/health-public.json"))
STATE = Path(os.environ.get("FRP_ALERT_STATE", "/var/lib/frp-manager/alert-state.json"))
STATUS = Path(os.environ.get("FRP_ALERT_STATUS", "/var/lib/frp-manager/alert-status.json"))
TIMEOUT = 8

def parse(data, now=None):
    if now is None:
        now = datetime.now(timezone.utc)
    when = datetime.fromisoformat(data["sampled_at"].replace("Z", "+00:00"))
    if when.tzinfo is None or (now-when).total_seconds() > 120:
        return {"collector": "stale"}
    states = {"collector": "available"}
    for item in data["states"]:
        if not isinstance(item,dict):
            continue
        subject = item.get("subject")
        state = item.get("state")
        if subject and isinstance(state,str):
            states[subject] = state.lower()
    return states

def changes(before, after, now=None, cooldown=600):
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    notices=[]
    for subject, state in after.items():
        previous=before.get("states",{}).get(subject)
        if previous is None or previous==state:
            continue
        unhealthy=state not in ("running","connected","available")
        key=subject+":"+state
        last=before.get("sent",{}).get(key,0)
        if unhealthy and now-last>=cooldown:
            notices.append((subject,state))
    return notices

def atomic_write(path,payload,mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=".frp-alert-",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as out:
            json.dump(payload,out)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp,mode)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def send(webhook, notices):
    if not notices:
        return
    message="FRP Manager alert: "+", ".join(subject+"="+state for subject,state in notices)
    payload=json.dumps({"content":message[:1800]}).encode()
    request=urllib.request.Request(webhook,data=payload,headers={"Content-Type":"application/json","User-Agent":"FRP-Manager-Alert/1"},method="POST")
    with urllib.request.urlopen(request,timeout=TIMEOUT) as result:
        if result.status not in (200,204):
            raise RuntimeError("Webhook refused the notification")

def run():
    webhook=os.environ.get("FRP_ALERT_WEBHOOK_URL","")
    if not webhook:
        return {"enabled":False,"result":"not_configured"}
    if not webhook.startswith("https://") or "@" in webhook or len(webhook)>1024:
        raise ValueError("Webhook URL must be a valid HTTPS URL without credentials")
    now=datetime.now(timezone.utc).timestamp()
    try:
        previous=json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError,ValueError):
        previous={"states":{},"sent":{}}
    current=parse(json.loads(SOURCE.read_text(encoding="utf-8")))
    notices=changes(previous,current,now)
    send(webhook,notices)
    sent=previous.get("sent",{})
    for subject,state in notices:
        sent[subject+":"+state]=now
    atomic_write(STATE,{"states":current,"sent":sent})
    atomic_write(STATUS,{"enabled":True,"checked_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),
                         "monitored_subjects":len(current),"alerts_sent":len(notices)},mode=0o644)
    return {"enabled":True,"alerts_sent":len(notices)}

if __name__=="__main__":
    run()
