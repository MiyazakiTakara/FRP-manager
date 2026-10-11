#!/usr/bin/env python3
"""OVH read-only FRPS hardening checks without releasing secrets."""
import json
from pathlib import Path
import subprocess
import sys
import tomllib

CONFIG=Path("/etc/frp/frps.toml")

def assess(config,mode):
    checks=[]
    def add(name,pass_condition,explanation):
        checks.append({"name":name,"result":"passed" if pass_condition else "warning","detail":explanation})
    tls=config.get("transport",{}).get("tls",{})
    add("FRPS enforced TLS", tls.get("force") is True,
        "Forced TLS" if tls.get("force") is True else "TLS enforcement is not explicitly confirmed")
    auth=config.get("auth",{})
    method=auth.get("method","token")
    token_source=auth.get("tokenSource",{})
    file_path=(token_source.get("file") or {}).get("path") if isinstance(token_source,dict) else None
    token_file_ok=False
    if method=="token" and isinstance(token_source,dict) and token_source.get("type")=="file" and isinstance(file_path,str) and file_path.startswith("/"):
        try:
            token_path=Path(file_path)
            token_file_ok=token_path.is_file() and token_path.stat().st_size>0
        except OSError:
            token_file_ok=False
    direct_token=method=="token" and bool(auth.get("token"))
    configured=direct_token or token_file_ok
    add("FRPS authentication",configured,
        "Token authentication configured via protected file" if token_file_ok else
        "Token authentication configured" if direct_token else
        "Check FRPS authentication settings")
    allowed=config.get("allowPorts",[])
    add("Port allowlist",isinstance(allowed,list) and 0<len(allowed)<100,
        "FRPS port allowlist exists" if isinstance(allowed,list) and allowed else "Port allowlist missing or unverified")
    add("Root-owned configuration",mode&0o077==0,"No group/other permission" if mode&0o077==0 else "Config permissions are broader than root-only")
    return checks

def main():
    try:
        with CONFIG.open("rb") as stream:
            config=tomllib.load(stream)
        checks=assess(config,CONFIG.stat().st_mode)
        active=subprocess.run(["/usr/bin/systemctl","is-active","frps.service"],
            capture_output=True,text=True,timeout=4,check=False).stdout.strip()=="active"
        checks.append({"name":"FRPS service","result":"passed" if active else "warning",
                       "detail":"Service running" if active else "Service not confirmed running"})
        result={"available":True,"scope":"FRPS server configuration and service only","checks":checks}
    except (OSError,ValueError,TypeError):
        result={"available":False,"checks":[],"reason":"FRPS security config unavailable"}
    json.dump(result,sys.stdout,separators=(",",":"))
    print()

if __name__=="__main__":
    main()
