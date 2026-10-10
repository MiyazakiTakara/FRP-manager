from urllib.parse import urlencode
import os
import logging
import json
import ipaddress
import re
import hmac
import tempfile
import secrets
import time
import httpx
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

# Import the existing read-only FRP integration.
from app import get_tunnels, get_ovh, read_config

ISSUER = os.environ["OIDC_ISSUER"].rstrip("/")
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
PUBLIC_URL = os.environ["APP_PUBLIC_URL"].rstrip("/")
SESSION_SECRET = os.environ["SESSION_SECRET"]

ROLES = ("frp-admin", "frp-operator", "frp-viewer")
from session_store import (
    initialize,
    create_session,
    get_session,
    revoke_session,
    audit,
)

initialize()

logger = logging.getLogger("frp-manager.auth")

app = FastAPI(
    title="FRP Manager",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=True,
    same_site="lax",
    max_age=1800,
)

oauth = OAuth()
oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=ISSUER + "/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
    code_challenge_method="S256",
)


async def introspect(access_token):
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(
            ISSUER + "/protocol/openid-connect/token/introspect",
            data={"token": access_token},
            auth=(CLIENT_ID, CLIENT_SECRET),
        )
        response.raise_for_status()
        return response.json()


def permitted_roles(data):
    resource = data.get("resource_access") or {}
    client = resource.get(CLIENT_ID) or {}
    assigned = client.get("roles") or []

    return [role for role in ROLES if role in assigned]


async def current_user(request: Request):
    sid = request.session.get("sid")
    session = get_session(sid)

    if not session:
        raise HTTPException(401, "Authentication required")

    try:
        data = await introspect(session["access_token"])
    except Exception:
        raise HTTPException(503, "Keycloak unavailable")

    if not data.get("active"):
        revoke_session(sid)
        request.session.clear()
        raise HTTPException(401, "Invalid session")

    roles = permitted_roles(data)
    if not roles:
        raise HTTPException(403, "Missing FRP Manager role")

    # Refresh the session cookie lifetime.
    request.session["sid"] = sid

    return {
        "sub": session["sub"],
        "name": session["name"],
        "roles": roles,
    }


@app.get("/api/health")
async def health():
    return {"application": "FRP Manager", "status": "running",
            "authentication": "keycloak"}


@app.get("/login")
async def login(request: Request):
    sid = request.session.get("sid")

    if sid and get_session(sid):
        try:
            await current_user(request)
            return RedirectResponse("/", status_code=303)
        except HTTPException:
            pass

    request.session.clear()
    return await oauth.keycloak.authorize_redirect(
        request,
        PUBLIC_URL + "/auth/callback",
    )


@app.get("/auth/callback")
async def callback(request: Request):
    try:
        token = await oauth.keycloak.authorize_access_token(request)
        data = await introspect(token["access_token"])
    except Exception as exc:
        logger.error("OIDC callback failed: %s", type(exc).__name__)
        return HTMLResponse(
            "<h1>Login failed</h1>",
            status_code=401,
        )

    if not data.get("active"):
        return HTMLResponse("Inactive token", status_code=401)

    roles = permitted_roles(data)
    if not roles:
        audit("login", "denied", subject=data.get("sub"))
        return HTMLResponse(
            "<h1>Access denied</h1>"
            "<p>The frp-manager client role is required.</p>",
            status_code=403,
        )

    userinfo = token.get("userinfo") or {}
    sub = userinfo.get("sub") or data.get("sub")

    if not sub:
        return HTMLResponse(
            "Missing user identifier",
            status_code=401,
        )

    now = int(time.time())
    token_expiry = data.get("exp")

    if not token_expiry:
        token_expiry = now + int(token.get("expires_in", 0))

    if int(token_expiry) <= now:
        return HTMLResponse("Token expired", status_code=401)

    sid = create_session(
        subject=sub,
        display_name=(
            userinfo.get("name")
            or userinfo.get("preferred_username")
            or sub
        ),
        access_token=token["access_token"],
        token_expires_at=token_expiry,
        id_token=token.get("id_token"),
    )

    request.session.clear()
    request.session["sid"] = sid

    audit("login", "success", subject=sub)

    return RedirectResponse("/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    sid = request.session.get("sid")
    session = get_session(sid)

    if sid:
        revoke_session(sid)

    request.session.clear()

    audit(
        "logout",
        "success",
        subject=session["sub"] if session else None,
    )

    endpoint = ISSUER + "/protocol/openid-connect/logout"

    params = {
        "client_id": CLIENT_ID,
        "post_logout_redirect_uri": PUBLIC_URL + "/logged-out",
    }

    if session and session.get("id_token"):
        params["id_token_hint"] = session["id_token"]

    response = RedirectResponse(
        endpoint + "?" + urlencode(params),
        status_code=303,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/me")
async def me(user=Depends(current_user)):
    return user


@app.get("/api/tunnels")
async def tunnels(user=Depends(current_user)):
    try:
        return get_tunnels()
    except Exception:
        raise HTTPException(503, "Unable to read tunnels")


@app.get("/api/ovh")
async def ovh(user=Depends(current_user)):
    try:
        return get_ovh()
    except Exception:
        raise HTTPException(503, "Unable to read remote server status")


@app.get("/api/integrations/homepage")
async def homepage(user=Depends(current_user)):
    try:
        result = get_tunnels()
    except Exception:
        raise HTTPException(503, "Monitoring unavailable")

    if result["active"] is None:
        raise HTTPException(503, "Monitoring unavailable")

    return {"active": result["active"], "total": result["total"]}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    sid = request.session.get("sid")
    if not get_session(sid):
        return RedirectResponse("/login", status_code=303)

    user = await current_user(request)

    page = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FRP Manager</title>
<style>
:root {
  color-scheme: dark;
  font-family: system-ui, sans-serif;
  background: #15181c;
  color: #e9ecef;
}
* { box-sizing: border-box; }
body { margin: 0; }
header {
  padding: 18px max(24px, calc((100vw - 1050px)/2));
  border-bottom: 1px solid #353a40;
  display: flex; justify-content: space-between; align-items: center;
}
main { max-width: 1050px; margin: 48px auto; padding: 0 24px; }
h1 { font-size: 30px; margin: 0 0 8px; }
p { color: #b4bbc2; }
a { color: #b3d5ff; }
.stats { display: flex; gap: 36px; margin: 36px 0; }
.stat strong { display: block; font-size: 36px; }
.stat span { color: #b4bbc2; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 17px 12px; text-align: left;
         border-bottom: 1px solid #353a40; }
th { color: #b4bbc2; font-weight: 500; }
code { font-size: 13px; overflow-wrap: anywhere; }
.error { color: #ffb8b8; }
:focus-visible { outline: 3px solid #b3d5ff; outline-offset: 4px; }
@media(max-width:600px) {
  header { padding: 16px; }
  main { margin-top: 24px; padding: 0 16px; }
  .stats { gap: 28px; }
}
</style>
</head>
<body>
<header><strong>FRP Manager</strong><nav><a href="/updates">Updates</a> &nbsp; <a href="/logout">Sign out</a></nav></header>
<main>
  <h1>Tunnels</h1>
  __ADD_TUNNEL__
  <p>Configuration and status from your FRP infrastructure.</p>
  <div class="stats">
    <div class="stat"><strong id="active">...</strong><span>Active</span></div>
    <div class="stat"><strong id="total">...</strong><span>Total</span></div>
  </div>
  <div id="message" role="status" aria-live="polite"></div>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Name</th><th>Protocol</th>
      <th>Public address</th><th>Target</th><th>Status</th><th id="actions-heading" hidden>Actions</th></tr></thead>
    <tbody id="tunnels"></tbody>
  </table>
  </div>
</main>
<script>
window.allowManage=__CAN_MANAGE__;
if(window.allowManage)document.getElementById("actions-heading").hidden=false;
async function load() {
  const message = document.getElementById("message");
  try {
    const response = await fetch("/api/tunnels");
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    document.getElementById("active").textContent = data.active ?? "?";
    document.getElementById("total").textContent = data.total;
    const tbody = document.getElementById("tunnels");
    tbody.replaceChildren();
    if (!data.tunnels.length) message.textContent = "No tunnels configured.";
    for (const tunnel of data.tunnels) {
      const tr = document.createElement("tr");
      const values = [
        tunnel.name, tunnel.protocol.toUpperCase(),
        tunnel.public_ip + ":" + tunnel.public_port,
        tunnel.local_ip + ":" + tunnel.local_port,
        tunnel.status
      ];
      for (const value of values) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td);
      }
      if (window.allowManage) {
        const td=document.createElement("td");
        const link=document.createElement("a");
        link.href="/tunnels/manage?name="+encodeURIComponent(tunnel.name);
        link.textContent="Edit / Delete";
        td.appendChild(link);tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
  } catch (error) {
    message.className = "error";
    message.textContent = "Unable to load tunnel status: " + error.message;
  }
}
load();
</script>
</body></html>
"""
    page=page.replace("__CAN_MANAGE__", "true" if "frp-admin" in user["roles"] else "false")
    return page.replace("__ADD_TUNNEL__", '<p><a href="/tunnels/new">+ Add tunnel (preview)</a></p>' if any(r in user["roles"] for r in ("frp-admin", "frp-operator")) else "")


@app.get("/logged-out", response_class=HTMLResponse)
async def logged_out():
    return HTMLResponse(
        """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Signed out - FRP Manager</title>
</head>
<body style="font-family:system-ui;max-width:520px;
margin:12vh auto;padding:24px">
<h1>Signed out</h1>
<p>Your FRP Manager session has ended.</p>
<a href="/login">Sign in again</a>
</body>
</html>""",
        headers={"Cache-Control": "no-store"},
    )


# Register the administrator-only update interface.
from update_web import install_update_routes
install_update_routes(app, current_user)


# Safe tunnel creation preview. No configuration writes or FRPC restarts.
async def can_preview_tunnel(user=Depends(current_user)):
    if not any(role in user["roles"] for role in ("frp-admin", "frp-operator")):
        raise HTTPException(403, "Operator or administrator role required")
    return user


def validate_tunnel_candidate(data):
    if not isinstance(data, dict):
        raise HTTPException(422, "Invalid tunnel definition")
    if set(data) != {"name", "protocol", "local_ip", "local_port", "public_port"}:
        raise HTTPException(422, "Unexpected or missing fields")
    name = data["name"]
    protocol = data["protocol"]
    host = data["local_ip"]
    local_port = data["local_port"]
    public_port = data["public_port"]
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
        raise HTTPException(422, "Name must be 1-64 characters (letters, numbers, underscore or hyphen)")
    if protocol not in ("tcp", "udp"):
        raise HTTPException(422, "Only TCP and UDP tunnels are supported")
    if not isinstance(host, str):
        raise HTTPException(422, "Invalid local IPv4 address")
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        raise HTTPException(422, "Local address must be a valid IPv4 address")
    if address.is_multicast or address.is_unspecified or address.is_reserved or address.is_loopback:
        raise HTTPException(422, "Local address is not a permitted target")
    for key, value in (("local_port", local_port), ("public_port", public_port)):
        if type(value) is not int or not 1 <= value <= 65535:
            raise HTTPException(422, key + " must be an integer between 1 and 65535")
    try:
        config = read_config()
    except Exception:
        raise HTTPException(503, "Unable to read current FRPC configuration")
    proxies = config.get("proxies", [])
    if not isinstance(proxies, list):
        raise HTTPException(503, "Unexpected FRPC configuration format")
    for proxy in proxies:
        if not isinstance(proxy, dict):
            raise HTTPException(503, "Unexpected FRPC proxy entry")
        if proxy.get("name", "").lower() == name.lower():
            raise HTTPException(409, "Tunnel name is already in use")
        if str(proxy.get("type", "")).lower() == protocol and proxy.get("remotePort") == public_port:
            raise HTTPException(409, "Public port is already configured for this protocol")
    return {
        "name": name,
        "type": protocol,
        "localIP": str(address),
        "localPort": local_port,
        "remotePort": public_port,
    }


@app.get("/tunnels/new", response_class=HTMLResponse)
async def new_tunnel_page(request: Request, user=Depends(can_preview_tunnel)):
    token = secrets.token_urlsafe(32)
    request.session["tunnel_preview_csrf"] = token
    html = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Add tunnel - FRP Manager</title>
<style>
:root{color-scheme:dark}body{font:16px system-ui;background:#15181c;color:#e9ecef;max-width:660px;margin:48px auto;padding:0 22px}
a{color:#acd0ff}label{display:block;margin:16px 0 5px}
input,select,button{font:inherit;padding:10px;border-radius:6px}
input,select{background:#252a30;color:#fff;border:1px solid #59616a;width:100%}
button{margin-top:18px;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#252a30;padding:18px;border-radius:8px}
.note{color:#bdc3ca}.error{color:#ffb5b5}
</style></head><body><p><a href="/">← Back to tunnels</a></p>
<h1>Add tunnel</h1><p class="note">Validate the tunnel before creating it. Preview is read-only; creation requires administrator approval and may restart FRPC.</p>
<form id="form">
<label for="name">Tunnel name</label><input id="name" maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,63}" required placeholder="game-udp">
<label for="protocol">Protocol</label><select id="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
<label for="local_ip">Local IPv4 target</label><input id="local_ip" required placeholder="192.168.1.37">
<label for="local_port">Local port</label><input id="local_port" type="number" min="1" max="65535" required>
<label for="public_port">Public port</label><input id="public_port" type="number" min="1" max="65535" required>
<button type="submit">Validate and preview</button></form>
<p class="note">Port availability on the remote FRPS firewall is not verified by this preview.</p>
<div id="feedback" role="status" aria-live="polite"></div><pre id="preview" hidden></pre><button id="create" type="button" hidden>Create tunnel</button><p id="result" role="status"></p>
<script>
const csrf="__TOKEN__";
document.getElementById("form").addEventListener("submit",async e=>{
 e.preventDefault();const feedback=document.getElementById("feedback");
 const preview=document.getElementById("preview");preview.hidden=true;document.getElementById("create").hidden=true;feedback.textContent="Validating...";
 const value=id=>document.getElementById(id).value;
 const body={name:value("name"),protocol:value("protocol"),local_ip:value("local_ip"),
 local_port:Number(value("local_port")),public_port:Number(value("public_port"))};
 try{
  const r=await fetch("/api/tunnels/preview",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body)});
  const data=await r.json();
  if(!r.ok){feedback.className="error";feedback.textContent=data.detail||"Validation failed";return;}
  feedback.className="";feedback.textContent="Validation passed. Preview generated; no tunnel has been created.";
  preview.hidden=false;preview.textContent=data.toml_preview;
  document.getElementById("create").hidden=!data.create_enabled;
 }catch(err){feedback.className="error";feedback.textContent="Unable to validate tunnel."}
});
document.getElementById("create").addEventListener("click",async()=>{
 if(!confirm("Create this tunnel and restart FRPC? Existing tunnels will be checked."))return;
 const value=id=>document.getElementById(id).value;
 const body={name:value("name"),protocol:value("protocol"),local_ip:value("local_ip"),
 local_port:Number(value("local_port")),public_port:Number(value("public_port"))};
 const r=await fetch("/api/tunnels/create",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body)});
 const result=document.getElementById("result");
 result.textContent=r.ok?"Creation queued. Check result below in a few seconds.":JSON.stringify(await r.json());
 if(r.ok){document.getElementById("create").hidden=true;setTimeout(async()=>{
 const res=await fetch("/api/tunnels/create-status");if(res.ok)result.textContent=JSON.stringify(await res.json());
 },7000);}
});
</script></body></html>"""
    return HTMLResponse(html.replace("__TOKEN__", token), headers={"Cache-Control": "no-store"})


@app.post("/api/tunnels/preview")
async def preview_tunnel(request: Request, user=Depends(can_preview_tunnel)):
    if request.headers.get("origin") != PUBLIC_URL:
        raise HTTPException(403, "Invalid origin")
    expected = request.session.get("tunnel_preview_csrf", "")
    received = request.headers.get("x-csrf-token", "")
    if not expected or not hmac.compare_digest(expected, received):
        raise HTTPException(403, "Invalid CSRF token")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "Expected JSON")
    if int(request.headers.get("content-length", "0") or "0") > 4096:
        raise HTTPException(413, "Request is too large")
    try:
        payload = await request.json()
    except ValueError:
        raise HTTPException(422, "Invalid JSON")
    tunnel = validate_tunnel_candidate(payload)
    preview = (
        "[[proxies]]\\n"
        + "name = " + json.dumps(tunnel["name"]) + "\\n"
        + "type = " + json.dumps(tunnel["type"]) + "\\n"
        + "localIP = " + json.dumps(tunnel["localIP"]) + "\\n"
        + "localPort = " + str(tunnel["localPort"]) + "\\n"
        + "remotePort = " + str(tunnel["remotePort"]) + "\\n"
    )
    return {"valid": True, "mode": "preview-only", "create_enabled": (Path("/etc/frp-manager/tunnel-writes-enabled").is_file() and "frp-admin" in user["roles"]), "toml_preview": preview,
            "note": "Remote FRPS firewall and port availability are not verified."}


TUNNEL_REQUEST = Path("/var/lib/frp-manager/tunnel-create-request.json")
TUNNEL_RESULT = Path("/var/lib/frp-manager/tunnel-create-status.json")
TUNNEL_ENABLED = Path("/etc/frp-manager/tunnel-writes-enabled")


@app.post("/api/tunnels/create")
async def create_tunnel(request: Request, user=Depends(current_user)):
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403, "Administrator role required")
    if not TUNNEL_ENABLED.is_file():
        raise HTTPException(503, "Tunnel creation is not enabled on this host")
    if request.headers.get("origin") != PUBLIC_URL:
        raise HTTPException(403, "Invalid origin")
    token = request.session.get("tunnel_preview_csrf", "")
    if not token or not hmac.compare_digest(token, request.headers.get("x-csrf-token", "")):
        raise HTTPException(403, "Invalid CSRF token")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "Expected JSON")
    if int(request.headers.get("content-length", "0") or "0") > 4096:
        raise HTTPException(413, "Request too large")
    try:
        data = await request.json()
    except ValueError:
        raise HTTPException(422, "Invalid JSON")
    candidate = validate_tunnel_candidate(data)
    request_data = {
        "tunnel": {
            "name": candidate["name"],
            "protocol": candidate["type"],
            "local_ip": candidate["localIP"],
            "local_port": candidate["localPort"],
            "public_port": candidate["remotePort"],
        }
    }
    if TUNNEL_REQUEST.exists():
        raise HTTPException(409, "Another tunnel operation is queued")
    fd, tmp_path = tempfile.mkstemp(prefix=".tunnel-queue-", dir=TUNNEL_REQUEST.parent)
    try:
        with os.fdopen(fd, "w") as file:
            json.dump(request_data, file)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(tmp_path, 0o600)
        # A single request slot. Atomic reservation before rename prevents overwriting.
        try:
            os.link(tmp_path, TUNNEL_REQUEST)
        except FileExistsError:
            raise HTTPException(409, "Another tunnel operation is queued")
    finally:
        os.unlink(tmp_path)
    return JSONResponse({"state": "queued", "name": candidate["name"]}, status_code=202)


@app.get("/api/tunnels/create-status")
async def create_tunnel_status(user=Depends(current_user)):
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403, "Administrator role required")
    if not TUNNEL_RESULT.exists():
        return {"state": "not-run"}
    try:
        record = json.loads(TUNNEL_RESULT.read_text())
        return {k: record[k] for k in ("state", "name", "protocol", "updated_at", "error", "rollback_failed") if k in record}
    except (OSError, ValueError):
        raise HTTPException(503, "Tunnel operation status unavailable")


@app.get("/tunnels/manage", response_class=HTMLResponse)
async def manage_tunnel(request: Request, user=Depends(current_user)):
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403, "Administrator role required")
    name=request.query_params.get("name","")
    config=read_config()
    proxy=next((p for p in config.get("proxies",[]) if p.get("name")==name),None)
    if proxy is None:
        raise HTTPException(404,"Tunnel not found")
    token=secrets.token_urlsafe(32)
    request.session["tunnel_manage_csrf"]=token
    html="""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Manage tunnel - FRP Manager</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>:root{color-scheme:dark}body{font:16px system-ui;background:#15181c;color:#eee;max-width:650px;margin:45px auto;padding:20px}
a{color:#acd0ff}label{display:block;margin-top:15px}input,button{font:inherit;padding:10px;margin-top:5px}input{width:100%;box-sizing:border-box}
button{cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style></head>
<body><a href="/">← Back to tunnels</a><h1>Manage tunnel</h1>
<p>Preview mode. Editing and deleting will require confirmation and safe backup/rollback.</p>
<form id="edit">
<label>Name (immutable)</label><input id="name" readonly>
<label>Protocol (immutable)</label><input id="protocol" readonly>
<label>Local IPv4 target</label><input id="local_ip" required>
<label>Local port</label><input id="local_port" required type="number" min="1" max="65535">
<label>Public port</label><input id="public_port" required type="number" min="1" max="65535">
<button type="submit">Preview edit</button>
</form><button id="delete">Preview delete</button>
<p id="result" role="status"></p><pre id="preview"></pre><button id="apply" type="button" hidden>Apply change</button>
<script>
const original=__DATA__;
const allowApply=__ALLOW_APPLY__;
let pending=null;
function showApply(data){pending=data;document.getElementById("apply").hidden=!allowApply;}

for(const key of ["name","protocol","local_ip","local_port","public_port"])
 document.getElementById(key).value=original[key];
document.getElementById("edit").addEventListener("submit",async e=>{
e.preventDefault();const draft={...original};
for(const key of ["local_ip","local_port","public_port"])draft[key]=document.getElementById(key).value;
draft.local_port=Number(draft.local_port);draft.public_port=Number(draft.public_port);
const r=await fetch("/api/tunnels/manage-preview",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":"__TOKEN__"},body:JSON.stringify({action:"edit",name:original.name,tunnel:draft})});
const d=await r.json();document.getElementById("result").textContent=r.ok?"Edit validation passed. No changes made.":d.detail;
 if(r.ok)showApply({action:"edit",name:original.name,tunnel:d.after});else{pending=null;document.getElementById("apply").hidden=true;}
document.getElementById("preview").textContent=r.ok?JSON.stringify(d,null,2):"";
});
document.getElementById("delete").addEventListener("click",async()=>{
 const confirmed=prompt("Type the tunnel name to preview deletion:");
 if(confirmed!==original.name)return;
 const r=await fetch("/api/tunnels/manage-preview",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":"__TOKEN__"},body:JSON.stringify({action:"delete",name:original.name})});
 const d=await r.json();document.getElementById("result").textContent=r.ok?"Delete preview ready. No changes made.":d.detail;
 if(r.ok)showApply({action:"delete",name:original.name});else{pending=null;document.getElementById("apply").hidden=true;}
 document.getElementById("preview").textContent=r.ok?JSON.stringify(d,null,2):"";
});
document.getElementById("apply").addEventListener("click",async()=>{
 if(!pending)return;
 const action=pending.action;
 if(action==="delete" && prompt("Confirm deletion. Enter tunnel name:")!==original.name)return;
 if(!confirm((action==="delete"?"Delete":"Edit")+" tunnel "+original.name+" and restart FRPC?"))return;
 const r=await fetch("/api/tunnels/manage-apply",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":"__TOKEN__"},body:JSON.stringify(pending)});
 const data=await r.json();
 document.getElementById("result").textContent=r.ok?"Operation queued. Check the status in a moment.":(data.detail||"Request failed");
 if(r.ok){document.getElementById("apply").hidden=true;pending=null;}
});
</script></body></html>"""
    values={"name":proxy["name"],"protocol":proxy["type"],"local_ip":proxy.get("localIP"),
            "local_port":proxy.get("localPort"),"public_port":proxy.get("remotePort")}
    return HTMLResponse(html.replace("__DATA__",json.dumps(values).replace("<","\\u003c")).replace("__TOKEN__",token).replace("__ALLOW_APPLY__", "true" if Path("/etc/frp-manager/tunnel-manage-enabled").is_file() else "false"),
                        headers={"Cache-Control":"no-store"})


@app.post("/api/tunnels/manage-preview")
async def manage_preview(request: Request,user=Depends(current_user)):
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403,"Administrator role required")
    if request.headers.get("origin") != PUBLIC_URL:
        raise HTTPException(403,"Invalid origin")
    expected=request.session.get("tunnel_manage_csrf","")
    if not expected or not hmac.compare_digest(expected,request.headers.get("x-csrf-token","")):
        raise HTTPException(403,"Invalid CSRF token")
    if int(request.headers.get("content-length","0") or "0") > 4096:
        raise HTTPException(413,"Request too large")
    try:
        payload=await request.json()
    except ValueError:
        raise HTTPException(422,"Invalid JSON")
    if type(payload) is not dict or payload.get("action") not in ("edit","delete"):
        raise HTTPException(422,"Invalid action")
    name=payload.get("name")
    config=read_config()
    proxy=next((p for p in config.get("proxies",[]) if p.get("name")==name),None)
    if proxy is None:
        raise HTTPException(404,"Tunnel not found")
    before={"name":proxy["name"],"protocol":proxy["type"],"local_ip":proxy.get("localIP"),
            "local_port":proxy.get("localPort"),"public_port":proxy.get("remotePort")}
    if payload["action"]=="delete":
        if set(payload)!={"action","name"}:
            raise HTTPException(422,"Unexpected fields")
        return {"mode":"preview-only","action":"delete","before":before,
                "note":"No configuration changes were applied"}
    if set(payload)!={"action","name","tunnel"}:
        raise HTTPException(422,"Unexpected fields")
    candidate=payload["tunnel"]
    if not isinstance(candidate,dict) or candidate.get("name")!=name or candidate.get("protocol")!=before["protocol"]:
        raise HTTPException(422,"Tunnel name and protocol cannot change")
    modified={**config,"proxies":[p for p in config.get("proxies",[]) if p.get("name")!=name]}
    # Validator reads live config; specifically check all other proxies here.
    for other in modified["proxies"]:
        if str(other.get("type","")).lower()==candidate.get("protocol") and other.get("remotePort")==candidate.get("public_port"):
            raise HTTPException(409,"Public port already in use")
    if set(candidate)!={"name","protocol","local_ip","local_port","public_port"}:
        raise HTTPException(422,"Unexpected tunnel fields")
    if not isinstance(candidate["local_ip"],str):
        raise HTTPException(422,"Invalid IPv4 address")
    try:
        addr=ipaddress.IPv4Address(candidate["local_ip"])
    except ipaddress.AddressValueError:
        raise HTTPException(422,"Invalid IPv4 address")
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved or addr.is_loopback:
        raise HTTPException(422,"Invalid IPv4 target")
    for port in ("local_port","public_port"):
        if type(candidate[port]) is not int or not 1<=candidate[port]<=65535:
            raise HTTPException(422,"Invalid port")
    return {"mode":"preview-only","action":"edit","before":before,"after":candidate,
            "note":"No configuration changes were applied"}


TUNNEL_MANAGE_ENABLED = Path("/etc/frp-manager/tunnel-manage-enabled")


@app.post("/api/tunnels/manage-apply")
async def manage_apply(request: Request, user=Depends(current_user)):
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403, "Administrator role required")
    if not TUNNEL_ENABLED.is_file() or not TUNNEL_MANAGE_ENABLED.is_file():
        raise HTTPException(503, "Tunnel editing and deletion are disabled")
    if request.headers.get("origin") != PUBLIC_URL:
        raise HTTPException(403, "Invalid origin")
    token=request.session.get("tunnel_manage_csrf","")
    if not token or not hmac.compare_digest(token,request.headers.get("x-csrf-token","")):
        raise HTTPException(403, "Invalid CSRF token")
    if request.headers.get("content-type","").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "Expected JSON")
    if int(request.headers.get("content-length","0") or "0") > 4096:
        raise HTTPException(413, "Request too large")
    try:
        payload=await request.json()
    except ValueError:
        raise HTTPException(422, "Invalid JSON")
    if type(payload) is not dict or payload.get("action") not in ("edit","delete"):
        raise HTTPException(422,"Invalid action")
    name=payload.get("name")
    if type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}",name):
        raise HTTPException(422,"Invalid tunnel name")
    config=read_config()
    proxy=next((p for p in config.get("proxies",[]) if p.get("name")==name),None)
    if proxy is None:
        raise HTTPException(404,"Tunnel not found")
    if payload["action"]=="edit":
        if set(payload)!={"action","name","tunnel"}:
            raise HTTPException(422,"Invalid request fields")
        candidate=payload["tunnel"]
        if type(candidate) is not dict or set(candidate)!={"name","protocol","local_ip","local_port","public_port"}:
            raise HTTPException(422,"Invalid tunnel fields")
        if candidate["name"]!=name or candidate["protocol"]!=proxy.get("type"):
            raise HTTPException(422,"Name and protocol cannot change")
        # Worker repeats all validation against the live config under an exclusive lock.
        with_others={"proxies":[p for p in config.get("proxies",[]) if p.get("name")!=name]}
        for p in with_others["proxies"]:
            if p.get("type")==candidate["protocol"] and p.get("remotePort")==candidate["public_port"]:
                raise HTTPException(409,"Public port already in use")
        if type(candidate["local_ip"]) is not str:
            raise HTTPException(422,"Invalid target")
        try:
            ip=ipaddress.IPv4Address(candidate["local_ip"])
        except ipaddress.AddressValueError:
            raise HTTPException(422,"Invalid IPv4 address")
        if ip.is_multicast or ip.is_loopback or ip.is_unspecified or ip.is_reserved:
            raise HTTPException(422,"Invalid target")
        for k in ("local_port","public_port"):
            if type(candidate[k]) is not int or not 1<=candidate[k]<=65535:
                raise HTTPException(422,"Invalid port")
    elif set(payload)!={"action","name"}:
        raise HTTPException(422,"Invalid request fields")
    if TUNNEL_REQUEST.exists():
        raise HTTPException(409,"Another tunnel operation is queued")
    fd,tmp=tempfile.mkstemp(prefix=".tunnel-manage-",dir=TUNNEL_REQUEST.parent)
    try:
        with os.fdopen(fd,"w") as output:
            json.dump(payload,output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(tmp,0o600)
        try:
            os.link(tmp,TUNNEL_REQUEST)
        except FileExistsError:
            raise HTTPException(409,"Another tunnel operation is queued")
    finally:
        os.unlink(tmp)
    return JSONResponse({"state":"queued","action":payload["action"],"name":name},status_code=202)
