from urllib.parse import urlencode
import os
import logging
import json
import secrets
import time
import httpx
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

# Import the existing read-only FRP integration.
from app import get_tunnels, get_ovh

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

    await current_user(request)

    return """
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
  <p>Configuration and status from your FRP infrastructure.</p>
  <div class="stats">
    <div class="stat"><strong id="active">...</strong><span>Active</span></div>
    <div class="stat"><strong id="total">...</strong><span>Total</span></div>
  </div>
  <div id="message" role="status" aria-live="polite"></div>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Name</th><th>Protocol</th>
      <th>Public address</th><th>Target</th><th>Status</th></tr></thead>
    <tbody id="tunnels"></tbody>
  </table>
  </div>
</main>
<script>
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
