#!/usr/bin/env python3
"""Root-only local FRP Manager configuration backup and offline integrity verifier.

Archives contain secrets. Mode 0600 and root-only directory are required.
This does not replace an off-host/offline disaster recovery copy.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile

DEST=Path("/var/backups/frp-manager")
FILES={
    "etc/frp/frpc.toml":Path("/etc/frp/frpc.toml"),
    "etc/frp-manager/allowed-ports.json":Path("/etc/frp-manager/allowed-ports.json"),
    "var/lib/frp-manager/history.db":Path("/var/lib/frp-manager/history.db"),
    "var/lib/frp-manager/health.db":Path("/var/lib/frp-manager/health.db"),
}
MAX_BYTES=512*1024*1024

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def files_to_archive(paths=FILES):
    content={}
    for name,path in paths.items():
        if path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size > MAX_BYTES:
            raise RuntimeError("Backup source exceeds size cap: "+name)
        content[name]=path.read_bytes()
    return content

def build(out_dir=DEST,paths=FILES):
    if os.geteuid()!=0:
        raise PermissionError("Backups require root")
    out_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    if out_dir.stat().st_mode & 0o077:
        raise PermissionError("Backup directory permissions are too broad")
    files=files_to_archive(paths)
    if "etc/frp/frpc.toml" not in files:
        raise RuntimeError("FRPC configuration is required")
    manifest={"schema":1,"created_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "files":{n:{"size":len(b),"sha256":sha256(b)} for n,b in files.items()}}
    fd,temp=tempfile.mkstemp(prefix=".frp-backup-",suffix=".tgz",dir=str(out_dir))
    os.chmod(temp,0o600)
    try:
        with os.fdopen(fd,"wb") as fp:
            with tarfile.open(fileobj=fp,mode="w:gz",format=tarfile.PAX_FORMAT) as tar:
                for name,blob in [*files.items(),("manifest.json",json.dumps(manifest,sort_keys=True).encode())]:
                    item=tarfile.TarInfo(name)
                    item.size=len(blob)
                    item.mtime=int(datetime.now(timezone.utc).timestamp())
                    item.mode=0o600
                    item.uid=item.gid=0
                    tar.addfile(item,io.BytesIO(blob))
            fp.flush()
            os.fsync(fp.fileno())
        verify(Path(temp))
        timestamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        final=out_dir/("frp-lxc-"+timestamp+".tgz")
        os.replace(temp,final)
        return final
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def verify(path):
    result={}
    with tarfile.open(path,mode="r:gz") as tar:
        members=tar.getmembers()
        names={i.name for i in members}
        if len(names)!=len(members) or "manifest.json" not in names or any(not i.isfile() for i in members):
            raise ValueError("Unexpected or duplicate archive members")
        manifest=json.load(tar.extractfile("manifest.json"))
        if manifest.get("schema")!=1 or not isinstance(manifest.get("files"),dict):
            raise ValueError("Invalid backup manifest")
        if names!={"manifest.json",*manifest["files"]}:
            raise ValueError("Manifest does not match archive")
        for name,meta in manifest["files"].items():
            if name not in FILES:
                raise ValueError("Unknown archived path")
            raw=tar.extractfile(name).read(MAX_BYTES+1)
            if len(raw)!=meta["size"] or sha256(raw)!=meta["sha256"]:
                raise ValueError("Checksum mismatch for "+name)
            result[name]=len(raw)
    return result

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--verify",type=Path,help="Verify an existing .tgz (no extraction)")
    args=parser.parse_args()
    if args.verify:
        result=verify(args.verify)
        print("VALID: "+", ".join(sorted(result)))
    else:
        path=build()
        print("Created and verified local root-only archive: "+str(path))
