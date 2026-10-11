#!/usr/bin/env python3
"""Bounded, redacted, read-only FRPS security events for FRP Manager."""
import collections
from datetime import datetime, timezone
import json
import re
import subprocess
import sys

CATEGORIES = [
    ("tls_rejected", "warning", re.compile(r"non-TLS connection|tls handshake|tlsonly", re.I)),
    ("authentication_failed", "high", re.compile(r"authentication failed|invalid token|token.*invalid|login.*fail|authorization failed", re.I)),
    ("port_rejected", "warning", re.compile(r"port not allowed|acquire port.*error|proxy name.*already in use", re.I)),
    ("proxy_failure", "warning", re.compile(r"new proxy.*error|failed to get work connection|no work connections available", re.I)),
    ("client_login", "info", re.compile(r"client login info:", re.I)),
    ("client_exit", "info", re.compile(r"client exit success", re.I)),
    ("proxy_created", "info", re.compile(r"new proxy .* success", re.I)),
]
SOURCE = re.compile(r"client login info: ip \[([0-9a-fA-F:.]+)\]")
PROXY = re.compile(r"\[([A-Za-z0-9][A-Za-z0-9_.-]{0,79})\]")
MAX_LINES = 1500
MAX_EVENTS = 200

def classify(message):
    # Do not relay raw FRPS log lines: may contain arbitrary error details.
    for category, severity, pattern in CATEGORIES:
        if pattern.search(message):
            details={}
            if category == "client_login":
                found=SOURCE.search(message)
                if found:
                    details["client_address"]=found.group(1)[:80]
            if category in ("port_rejected","proxy_failure","proxy_created"):
                candidates=PROXY.findall(message)
                if candidates:
                    details["proxy"]=candidates[-1]
            return category,severity,details
    return None

def read_events(lines):
    grouped={}
    for line in lines:
        try:
            raw=json.loads(line)
            message=raw.get("MESSAGE","")
            if not isinstance(message,str):
                continue
            classified=classify(message)
            if not classified:
                continue
            category,severity,details=classified
            ts=int(raw.get("__REALTIME_TIMESTAMP","0"))
            when=datetime.fromtimestamp(ts/1000000,timezone.utc).isoformat(timespec="seconds")
            # Group duplicates per 5 min bucket; preserve count and latest occurrence.
            bucket=ts//(300*1000000)
            key=(category, json.dumps(details,sort_keys=True),bucket)
            if key not in grouped:
                grouped[key]={"timestamp":when,"category":category,"severity":severity,
                              "details":details,"count":0}
            grouped[key]["count"]+=1
            grouped[key]["timestamp"]=when
        except (ValueError,TypeError,OverflowError,OSError):
            continue
    return sorted(grouped.values(),key=lambda x:x["timestamp"],reverse=True)[:MAX_EVENTS]

def main():
    # Fixed argv, no user input, no shell. Times limited; output is structured only.
    result=subprocess.run(["/usr/bin/journalctl","-u","frps.service","--since","24 hours ago",
        "-n",str(MAX_LINES),"--output=json","--no-pager"],capture_output=True,text=True,timeout=15,check=True)
    payload={"source":"frps_journal","window_hours":24,"events":read_events(result.stdout.splitlines())}
    json.dump(payload,sys.stdout,separators=(",",":"))
    sys.stdout.write("\n")

if __name__=="__main__":
    main()
