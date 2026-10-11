#!/usr/bin/env python3
"""Read-only, redacted FRPS dashboard metrics exporter for limited sudo execution.

Reads root-owned FRPS TOML, connects only to localhost admin API, emits counters
for existing named proxies. Missing dashboard API => reports unavailable.
No configuration, token, authentication secrets or client IPs are exported.
"""
from datetime import datetime, timezone
import base64
import json
from pathlib import Path
import re
import sys
import tomllib
import urllib.error
import urllib.request
from urllib.parse import quote

CONFIG=Path("/etc/frp/frps.toml")
MAX_PROXIES=100
NAME=re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")

def decode_proxy(item):
    if not isinstance(item,dict) or not NAME.fullmatch(str(item.get("name",""))):
        return None
    name=item["name"]
    counters={}
    for prop in ("todayTrafficIn","todayTrafficOut","curConns"):
        value=item.get(prop)
        counters[prop]=value if type(value) is int and 0<=value<10**17 else None
    return {"name":name,"status":str(item.get("status","unknown"))[:24],
            "counters":counters}

def read_dashboard(configuration=CONFIG):
    with configuration.open("rb") as fd:
        config=tomllib.load(fd)
    web=config.get("webServer",{})
    port=web.get("port")
    if type(port) is not int or not 1<=port<=65535:
        return {"available":False,"reason":"FRPS dashboard API not configured","proxies":[]}
    user=str(web.get("user",""))
    password=str(web.get("password",""))
    if not user or not password:
        return {"available":False,"reason":"FRPS dashboard authentication unavailable","proxies":[]}
    header=base64.b64encode((user+":"+password).encode()).decode()
    proxies=[]
    any_success=False
    try:
        for protocol in ("tcp","udp","http","https","stcp","xtcp","tcpmux"):
            url="http://127.0.0.1:"+str(port)+"/api/proxy/"+protocol
            req=urllib.request.Request(url,headers={"Authorization":"Basic "+header,"Accept":"application/json"})
            try:
                with urllib.request.urlopen(req,timeout=5) as response:
                    data=response.read(128001)
                if len(data)>128000:
                    raise ValueError("Server returned excessive metrics")
                parsed=json.loads(data)
                entries=parsed.get("proxies") if isinstance(parsed,dict) else None
                if not isinstance(entries,list):
                    raise ValueError("Unexpected FRPS proxy response")
                any_success=True
                for raw in entries:
                    if len(proxies)>=MAX_PROXIES:
                        break
                    proxy=decode_proxy(raw)
                    if proxy:
                        proxy["protocol"]=protocol
                        proxies.append(proxy)
            except urllib.error.HTTPError as error:
                if error.code==404:
                    continue
                raise
        if not any_success:
            return {"available":False,"reason":"No supported FRPS proxy API endpoints","proxies":[]}
        for proxy in proxies[:10]:
            traffic_req=urllib.request.Request(
                "http://127.0.0.1:"+str(port)+"/api/traffic/"+quote(proxy["name"],safe=""),
                headers={"Authorization":"Basic "+header,"Accept":"application/json"})
            try:
                with urllib.request.urlopen(traffic_req,timeout=2) as response:
                    raw_traffic=response.read(8193)
                if len(raw_traffic)>8192:
                    continue
                traffic=json.loads(raw_traffic)
                inside=traffic.get("trafficIn")
                outside=traffic.get("trafficOut")
                if (type(inside) is list and type(outside) is list and
                    len(inside)==len(outside)==7 and
                    all(type(v) is int and 0<=v<10**17 for v in inside+outside)):
                    proxy["traffic7d"]={"in":inside,"out":outside}
            except (urllib.error.URLError,TimeoutError,ValueError,TypeError,AttributeError):
                continue
        return {"available":True,"source":"frps_admin_api",
                "timestamp":datetime.now(timezone.utc).isoformat(timespec="seconds"),"proxies":proxies}
    except (urllib.error.URLError,TimeoutError,ValueError,TypeError):
        return {"available":False,"reason":"FRPS dashboard API unavailable","proxies":[]}

def main():
    data=read_dashboard()
    json.dump(data,sys.stdout,separators=(",",":"))
    print()

if __name__=="__main__":
    main()
