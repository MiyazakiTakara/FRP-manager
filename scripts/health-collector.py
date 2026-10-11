#!/usr/bin/env python3
"""Read-only FRPC connectivity sampler: events on transitions, not per packet."""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import tomllib
import urllib.request

DB = Path("/var/lib/frp-manager/health.db")
CONFIG = Path("/etc/frp/frpc.toml")
MAX_EVENTS = 10000
PUBLIC = Path("/var/lib/frp-manager/health-public.json")

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def snapshot(config, api=None, service_ok=True):
    """Return conservative proxy and upstream states. No payload inspection."""
    proxies = config.get("proxies", [])
    if api is None:
        return {"upstream": "unknown", "monitoring": "unavailable",
                "tunnels": [{"name":p.get("name",""),"protocol":p.get("type",""),
                             "state":"unknown","reason":None} for p in proxies]}
    status = {}
    for protocol, entries in api.items():
        if not isinstance(entries, list):
            continue
        for item in entries:
            if isinstance(item, dict) and item.get("name"):
                status[(protocol.lower(),item["name"])] = item
    tunnels = []
    for p in proxies:
        key = (str(p.get("type","")).lower(),p.get("name"))
        item = status.get(key)
        tunnels.append({"name":p.get("name",""),"protocol":key[0],
                        "state":str(item.get("status","unknown")).lower() if item else "unknown",
                        "reason":str(item.get("err") or "")[:180] if item else None})
    # A running proxy proves recent successful FRPS registration. With no
    # running proxies, /api/status alone cannot prove FRPS disconnected.
    upstream = "connected" if any(t["state"]=="running" for t in tunnels) else "unknown"
    return {"upstream": upstream, "monitoring":"available","tunnels":tunnels}

def read_api(config):
    web=config["webServer"]
    host=web.get("addr","127.0.0.1")
    if host not in ("127.0.0.1","localhost","::1","192.168.1.148"):
        raise ValueError("Unexpected FRPC API address")
    port=int(web.get("port",7400))
    auth=base64.b64encode((str(web.get("user",""))+":"+str(web.get("password",""))).encode()).decode()
    req=urllib.request.Request("http://"+host+":"+str(port)+"/api/status",
                                headers={"Authorization":"Basic "+auth})
    with urllib.request.urlopen(req,timeout=4) as res:
        return json.load(res)

def sample():
    with CONFIG.open("rb") as stream:
        config=tomllib.load(stream)
    try:
        api=read_api(config)
    except Exception:
        api=None
    return snapshot(config,api)

def record(db,sample_data,at):
    db.execute("CREATE TABLE IF NOT EXISTS health_state (subject TEXT PRIMARY KEY, state TEXT NOT NULL, changed_at TEXT NOT NULL)")
    db.execute("""CREATE TABLE IF NOT EXISTS health_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recorded_at TEXT NOT NULL, subject TEXT NOT NULL, previous TEXT,
        current TEXT NOT NULL, reason TEXT)""")
    db.execute("CREATE INDEX IF NOT EXISTS health_events_at ON health_events(recorded_at)")
    subjects = {"frps_connection": (sample_data["upstream"],None),
                "frpc_api": (sample_data["monitoring"],None)}
    for t in sample_data["tunnels"]:
        subjects["proxy:"+t["protocol"]+":"+t["name"]] = (t["state"],t.get("reason"))
    known={row[0]:row[1] for row in db.execute("SELECT subject,state FROM health_state")}
    for subject,(state,reason) in subjects.items():
        if known.get(subject)!=state:
            db.execute("INSERT INTO health_events(recorded_at,subject,previous,current,reason) VALUES(?,?,?,?,?)",
                       (at,subject,known.get(subject),state,reason))
            db.execute("INSERT INTO health_state(subject,state,changed_at) VALUES(?,?,?) ON CONFLICT(subject) DO UPDATE SET state=excluded.state,changed_at=excluded.changed_at",
                       (subject,state,at))
    for subject in set(known)-set(subjects):
        if subject.startswith("proxy:"):
            db.execute("DELETE FROM health_state WHERE subject=?",(subject,))
            db.execute("INSERT INTO health_events(recorded_at,subject,previous,current,reason) VALUES(?,?,?,?,?)",
                       (at,subject,known[subject],"removed",None))
    db.execute("DELETE FROM health_events WHERE id NOT IN (SELECT id FROM health_events ORDER BY id DESC LIMIT ?)",(MAX_EVENTS,))
    db.commit()

def publish(db):
    states=db.execute("SELECT subject,state,changed_at FROM health_state ORDER BY subject").fetchall()
    events=db.execute("SELECT recorded_at,subject,previous,current,reason FROM health_events ORDER BY id DESC LIMIT 200").fetchall()
    payload={"sampled_at":now(),
             "states":[dict(zip(("subject","state","changed_at"),r)) for r in states],
             "events":[dict(zip(("recorded_at","subject","previous","current","reason"),r)) for r in events]}
    with tempfile.NamedTemporaryFile(mode="w",dir=PUBLIC.parent,prefix=".health-",delete=False) as stream:
        path=Path(stream.name)
        json.dump(payload,stream)
        stream.write("\n")
    os.chmod(path,0o644)
    os.replace(path,PUBLIC)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--once",action="store_true")
    args=parser.parse_args()
    if not args.once:
        parser.error("--once required")
    DB.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(DB,timeout=10) as db:
        os.chmod(DB,0o600)
        record(db,sample(),now())
        publish(db)

if __name__=="__main__":
    main()
