"""Administrative update UI. Updates are triggered by a narrowly scoped systemd.path unit."""
import hmac
import json
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

STATE_DIR = Path("/var/lib/frp-manager")
REQUEST = STATE_DIR / "update-request"
STATUS = STATE_DIR / "update-status.json"
CHECK = STATE_DIR / "update-check.json"
SETTINGS = STATE_DIR / "update-settings.json"
PAUSED = STATE_DIR / "update-auto-paused"
REVISION = STATE_DIR / "deployed-revision"


def install_update_routes(app, current_user):
    async def require_admin(user=Depends(current_user)):
        if "frp-admin" not in user["roles"]:
            raise HTTPException(403, "Administrator role required")
        return user

    @app.get("/updates", response_class=HTMLResponse)
    async def updates_page(request: Request, user=Depends(require_admin)):
        token = secrets.token_urlsafe(32)
        request.session["update_csrf"] = token
        html = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Updates - FRP Manager</title>
<style>
body{font:16px system-ui;background:#15181c;color:#e9ecef;max-width:740px;
margin:50px auto;padding:0 22px;line-height:1.5}
a{color:#a5c7fb}button{padding:12px 20px;cursor:pointer}
pre{white-space:pre-wrap;background:#25292e;padding:16px;border-radius:8px}
</style></head><body><p><a href="/">← Back to tunnels</a></p>
<h1>Application updates</h1>
<p>Only FRP Manager source files are updated. FRP tunnels, secrets and session
data are not changed. Failed health checks trigger automatic source rollback.</p>
<p><label>Check interval (minutes) <input id="interval" type="number" min="1" max="1440" value="30"></label></p>
<p><label><input id="download" type="checkbox" checked> Automatically download updates (do not install)</label></p>
<button id="save">Save settings</button> <button id="start">Install latest version</button>
<p id="check" role="status"></p>
<pre id="status">Checking status...</pre>
<script>
const csrf = "__CSRF__";
async function check(){
 const r=await fetch("/api/update/check",{cache:"no-store"});
 if(r.ok){const d=await r.json();
 document.getElementById("check").textContent="Installed: "+(d.installed||"unknown")+" | Latest: "+(d.latest||"unknown")+" | Check: "+d.state+(d.paused?" | Automatic checks paused":"");
 document.getElementById("interval").value=d.interval_minutes;
 document.getElementById("download").checked=d.auto_download;
 }}
document.getElementById("save").addEventListener("click",async()=>{
 const r=await fetch("/api/update/settings",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify({interval_minutes:Number(document.getElementById("interval").value),auto_download:document.getElementById("download").checked})});
 const d=await r.json();alert(r.ok?"Settings saved":JSON.stringify(d));check();
});
async function status(){
 const r=await fetch("/api/update/status",{cache:"no-store"});
 if(r.ok)document.getElementById("status").textContent=
   JSON.stringify(await r.json(),null,2);
}
document.getElementById("start").addEventListener("click",async()=>{
 if(!confirm("Update FRP Manager now? Current panel connections may briefly drop."))return;
 const btn=document.getElementById("start");btn.disabled=true;
 try{
  const r=await fetch("/api/update/start",{method:"POST",
    headers:{"X-CSRF-Token":csrf}});
  const data=await r.json();
  document.getElementById("status").textContent=JSON.stringify(data,null,2);
 }catch(e){document.getElementById("status").textContent=String(e)}
 finally{btn.disabled=false}
});
status();check();setInterval(status,5000);setInterval(check,30000);
</script></body></html>"""
        return HTMLResponse(
            html.replace("__CSRF__", token),
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/api/update/status")
    async def update_status(user=Depends(require_admin)):
        if not STATUS.exists():
            return JSONResponse({"state": "not-run"}, headers={"Cache-Control": "no-store"})
        try:
            data = json.loads(STATUS.read_text())
            return JSONResponse({
                "state": str(data.get("state", "unknown")),
                "revision": str(data.get("revision", ""))[:50],
                "updated_at": str(data.get("updated_at", ""))[:50],
            }, headers={"Cache-Control": "no-store"})
        except (OSError, ValueError):
            raise HTTPException(503, "Update status unavailable")

    @app.post("/api/update/start")
    async def update_start(request: Request, user=Depends(require_admin)):
        origin = request.headers.get("origin", "")
        expected = os.environ["APP_PUBLIC_URL"].rstrip("/")
        # Origin can be absent for some clients; require the application origin.
        if origin != expected:
            raise HTTPException(403, "Invalid origin")
        expected_token = request.session.get("update_csrf", "")
        received_token = request.headers.get("x-csrf-token", "")
        if not expected_token or not hmac.compare_digest(expected_token, received_token):
            raise HTTPException(403, "Invalid CSRF token")
        try:
            fd = os.open(REQUEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise HTTPException(409, "Update already queued")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(user["sub"] + "\n")
        except Exception:
            REQUEST.unlink(missing_ok=True)
            raise
        return JSONResponse({"state": "queued"}, status_code=202)

    def csrf_ok(request):
        expected = request.session.get("update_csrf", "")
        received = request.headers.get("x-csrf-token", "")
        if not expected or not hmac.compare_digest(expected, received):
            raise HTTPException(403, "Invalid CSRF token")
        if request.headers.get("origin") != os.environ["APP_PUBLIC_URL"].rstrip("/"):
            raise HTTPException(403, "Invalid origin")

    @app.get("/api/update/check")
    async def check_status(user=Depends(require_admin)):
        try:
            result = json.loads(CHECK.read_text()) if CHECK.exists() else {}
            settings = json.loads(SETTINGS.read_text()) if SETTINGS.exists() else {}
            return JSONResponse({
                "state": result.get("state", "not-checked"),
                "installed": REVISION.read_text().strip() if REVISION.exists() else "",
                "latest": result.get("latest", ""),
                "checked_at": result.get("checked_at", ""),
                "downloaded": result.get("downloaded", False),
                "paused": PAUSED.exists(),
                "interval_minutes": settings.get("interval_minutes", 30),
                "auto_download": settings.get("auto_download", True),
            }, headers={"Cache-Control":"no-store"})
        except (ValueError, OSError):
            raise HTTPException(503, "Update checks unavailable")

    @app.post("/api/update/settings")
    async def update_settings(request: Request, user=Depends(require_admin)):
        csrf_ok(request)
        try:
            data = await request.json()
            interval = data["interval_minutes"]
            download = data["auto_download"]
            if type(interval) is not int or not 1 <= interval <= 1440 or type(download) is not bool:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise HTTPException(422, "Invalid settings")
        settings = {"interval_minutes":interval,"auto_download":download}
        tmp = SETTINGS.with_name("update-settings.tmp-" + secrets.token_hex(8))
        with tmp.open("x") as out:
            os.chmod(tmp, 0o600)
            json.dump(settings, out)
        os.replace(tmp, SETTINGS)
        return settings

