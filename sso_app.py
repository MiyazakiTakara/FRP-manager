from urllib.parse import urlencode
import os
import logging
import json
import asyncio
import ipaddress
import re
import hmac
import hashlib
import sqlite3
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
from app import get_tunnels, get_ovh, read_config, get_security_events, get_frps_metrics, get_frps_security
import ui_store

ISSUER = os.environ["OIDC_ISSUER"].rstrip("/")
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
PUBLIC_URL = os.environ["APP_PUBLIC_URL"].rstrip("/")
SESSION_SECRET = os.environ["SESSION_SECRET"]

ROLES = ("frp-admin", "frp-operator", "frp-viewer")
PORT_POLICY = Path("/etc/frp-manager/allowed-ports.json")


def check_public_port(protocol, port):
    if not PORT_POLICY.exists():
        return
    if PORT_POLICY.is_symlink():
        raise HTTPException(503, "Port policy is invalid")
    try:
        policy = json.loads(PORT_POLICY.read_text(encoding="utf-8"))
        if type(policy) is not dict or set(policy) != {"tcp", "udp"}:
            raise ValueError("Invalid policy")
        ranges = policy[protocol]
        if type(ranges) is not list:
            raise ValueError("Invalid ranges")
        allowed = False
        for item in ranges:
            if (type(item) is not list or len(item) != 2 or
                    any(type(n) is not int or not 1 <= n <= 65535 for n in item)
                    or item[0] > item[1]):
                raise ValueError("Invalid range")
            if item[0] <= port <= item[1]:
                allowed = True
        if not allowed:
            raise HTTPException(422, "Public port is not allowed by configured FRPS port policy")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(503, "Unable to validate FRPS port policy") from exc

from session_store import (
    initialize,
    create_session,
    get_session,
    revoke_session,
    audit,
    replace_tokens,
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

@app.exception_handler(401)
async def expired_session_handler(request: Request, exc: HTTPException):
    if request.method == "GET" and not request.url.path.startswith("/api/"):
        request.session.clear()
        return RedirectResponse("/login", status_code=303, headers={"Cache-Control": "no-store"})
    return JSONResponse({"detail": "Session expired. Please sign in again."},
                        status_code=401, headers={"Cache-Control": "no-store"})


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
        request.session.clear()
        raise HTTPException(401, "Authentication required")

    if session.get("refresh_token") and session["token_expires_at"] <= int(time.time()) + 90:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    ISSUER + "/protocol/openid-connect/token",
                    data={"grant_type": "refresh_token", "refresh_token": session["refresh_token"]},
                    auth=(CLIENT_ID, CLIENT_SECRET))
                response.raise_for_status()
                tokens = response.json()
            updated_expiry = int(time.time()) + int(tokens["expires_in"])
            replace_tokens(sid, tokens["access_token"], updated_expiry,
                           tokens.get("refresh_token", session["refresh_token"]),
                           tokens.get("id_token", session.get("id_token")))
            session["access_token"] = tokens["access_token"]
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (400, 401):
                revoke_session(sid)
                request.session.clear()
                raise HTTPException(401, "Session expired") from None
            raise HTTPException(503, "Keycloak token refresh unavailable") from None
        except (httpx.HTTPError, KeyError, ValueError):
            raise HTTPException(503, "Keycloak token refresh unavailable") from None

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
        refresh_token=token.get("refresh_token"),
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
        return await asyncio.to_thread(get_tunnels)
    except Exception:
        raise HTTPException(503, "Unable to read tunnels")


@app.get("/api/ovh")
async def ovh(user=Depends(current_user)):
    try:
        return await asyncio.to_thread(get_ovh)
    except Exception:
        raise HTTPException(503, "Unable to read remote server status")


@app.get("/api/integrations/homepage")
async def homepage(user=Depends(current_user)):
    try:
        result = await asyncio.to_thread(get_tunnels)
    except Exception:
        raise HTTPException(503, "Monitoring unavailable")

    if result["active"] is None:
        raise HTTPException(503, "Monitoring unavailable")

    return {"active": result["active"], "total": result["total"]}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    sid = request.session.get("sid")
    if not get_session(sid):
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    user = await current_user(request)

    page = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FRP Manager — Control Center</title>
<style>
:root{font:14px system-ui,-apple-system,"Segoe UI",sans-serif;color-scheme:dark;--bg:#0d1117;--surface:#161c26;--border:#30394a;--muted:#a4afc0;--text:#eef2f8;--accent:#92b9ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text)}a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{border-bottom:1px solid var(--border);background:var(--surface);padding:15px clamp(16px,3vw,40px);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.brand{font-weight:750;font-size:19px}.sub{font-size:12px;color:var(--muted)}.shell{display:grid;grid-template-columns:220px minmax(0,1fr);min-height:calc(100vh - 64px)}
aside{padding:20px 12px;border-right:1px solid var(--border);background:#121720}.nav{display:block;width:100%;padding:11px 14px;text-align:left;border:0;border-radius:8px;background:transparent;color:var(--muted);font:inherit;cursor:pointer}
.nav[aria-selected=true]{background:#253552;color:#fff;font-weight:650}main{padding:26px clamp(16px,3vw,42px);max-width:none;width:100%}
h1{font-size:26px;margin:0 0 6px}h2{font-size:16px;margin:0 0 14px}p{color:var(--muted)}.heading{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:22px}
.btn{border:1px solid var(--border);border-radius:8px;padding:9px 12px;background:#283243;color:var(--text);font:inherit;cursor:pointer}.btn:hover{background:#344259}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.card{background:var(--surface);border:1px solid var(--border);border-radius:11px;padding:18px;min-width:0}
.value{font-size:34px;font-weight:750;margin-top:12px}.muted{color:var(--muted)}.good{color:#83d4ab}.warn{color:#f7c77a}.bad{color:#f29b9b}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}input,select{font:inherit;background:#0c121c;color:var(--text);padding:9px 11px;border:1px solid var(--border);border-radius:7px}
input{min-width:180px}.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left}th,td{padding:12px 10px;border-bottom:1px solid var(--border);white-space:nowrap}
th{color:var(--muted);font-weight:600;font-size:12px}td{font-size:13px}.pill{border:1px solid var(--border);border-radius:20px;padding:3px 8px;display:inline-block;font-size:12px}
.note{font-size:12px;color:var(--muted)}.empty{padding:26px 10px;color:var(--muted)}.section{display:none}.section.active{display:block}
.live{display:inline-flex;align-items:center;gap:7px;color:#83d4ab;font-size:12px;font-weight:650}.live:before{content:"";background:#83d4ab;width:7px;height:7px;border-radius:50%;box-shadow:0 0 0 4px #83d4ab20}.live.stale{color:#f7c77a}.live.stale:before{background:#f7c77a;box-shadow:none}
.dashboard-lower{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(300px,1fr);gap:14px;margin-top:16px}.dashboard-lower .card{min-width:0}.flex-between{display:flex;justify-content:space-between;align-items:center;gap:12px}.mini-list{list-style:none;padding:0;margin:0}.mini-list li{border-bottom:1px solid var(--border);padding:10px 0;display:flex;justify-content:space-between;gap:12px}.mini-list li:last-child{border-bottom:0}.signal{font-size:12px;border-radius:5px;padding:3px 7px;background:#38404d}.signal.high{background:#50282d;color:#ffb2b2}.signal.warning{background:#493d26;color:#f7c77a}
.state{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);border-radius:18px;padding:4px 9px;font-size:12px;font-weight:650}
.state:before{content:"";height:7px;width:7px;border-radius:50%;background:currentColor}
.state.ok{color:#83d4ab;background:#19352855}.state.fail{color:#ff9e9e;background:#46262955}.state.unknown{color:#f7c77a;background:#493d2655}
.healthline{list-style:none;margin:0 0 20px;padding:0;display:grid;gap:8px}
.healthline li{display:flex;align-items:center;justify-content:space-between;gap:16px;border-left:3px solid var(--border);background:#1e2734;padding:10px 14px;border-radius:4px}
.healthline li.ok{border-color:#83d4ab}.healthline li.fail{border-color:#f29b9b}.healthline li.unknown{border-color:#f7c77a}
.severity-high{color:#ffa8a8;font-weight:750}.event-link{background:none;border:0;color:var(--accent);cursor:pointer;text-decoration:underline;font:inherit;padding:0}.event-link:hover{color:#fff}#incident{position:fixed;margin:auto;width:min(520px,calc(100vw - 32px));max-height:min(75vh,740px);overflow-y:auto;background:#161c26;color:#eef2f8;border:1px solid #42516a;border-radius:14px;padding:24px;box-shadow:0 24px 80px #0009}#incident::backdrop,#tunnel-modal::backdrop{background:#03070dc9}
#tunnel-modal{position:fixed;margin:auto;width:min(770px,calc(100vw - 24px));height:auto;max-height:88vh;overflow-y:auto;background:#161c26;border:1px solid #42516a;border-radius:14px;padding:14px;box-shadow:0 24px 80px #0009;color:#eef2f8}
.form-cols{display:grid;grid-template-columns:2fr 1fr;gap:12px}#tunnel-modal form label,#tunnel-confirm-line label{display:block;margin:12px 0;color:#b9c7d8;font-size:13px}#tunnel-modal form input,#tunnel-modal form select,#tunnel-modal textarea,#tunnel-metadata input,#tunnel-confirm-name{width:100%;margin-top:6px}#tunnel-metadata label{display:block;margin:10px 0;font-size:13px}#tunnel-modal .modal-actions{display:flex;justify-content:flex-end;gap:10px;margin:18px 0}.danger{color:#ffb6bd;background:#532b36}.review-list>div{padding:10px 0;border-bottom:1px solid #30394a}.review-list .changed{color:#f7c77a}.review-list .current{color:#a4afc0}.review-list strong{display:block;margin-bottom:4px}@media(max-width:600px){.form-cols{grid-template-columns:1fr}}
#tunnel-modal .flex-between{margin-bottom:10px}
#tunnel-modal::backdrop{background:#03070dd9}body:has(dialog[open]){overflow:hidden}.pager-disabled{opacity:.4}.severity-warning{color:#f7c77a}.value[data-state="connected"],.value[data-state="available"]{color:#83d4ab}.value[data-state="unknown"],.value[data-state="unavailable"]{color:#f7c77a}
@media(max-width:1080px){.dashboard-lower{grid-template-columns:1fr}}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px}@media(max-width:780px){.shell{grid-template-columns:1fr}aside{border-right:0;border-bottom:1px solid var(--border);display:flex;gap:4px;overflow-x:auto;padding:8px}.nav{width:auto;flex:none}main{padding:20px 14px}.grid{grid-template-columns:1fr}.heading{align-items:start}}
</style></head><body>
<header><div><div class="brand">FRP Manager</div><div class="sub">Infrastructure control center</div></div>
<div><span id="who" class="sub"></span> &nbsp; <a href="/updates">Updates</a> &nbsp; <a href="/logout">Sign out</a></div></header>
<div class="shell"><aside aria-label="Sections">
<button class="nav" aria-selected="true" data-tab="overview">Overview</button>
<button class="nav" aria-selected="false" data-tab="tunnels">Tunnels</button>
<button class="nav" aria-selected="false" data-tab="health">Health</button>
<button class="nav" aria-selected="false" data-tab="history">History</button>
<button class="nav" aria-selected="false" data-tab="security">Security Events</button><button class="nav" aria-selected="false" data-tab="diagnostics">Diagnostics</button><button class="nav" aria-selected="false" data-tab="topology">Topology</button><button class="nav" aria-selected="false" data-tab="alerts">Alerts</button><button class="nav" aria-selected="false" data-tab="backup">Backup & Recovery</button><button class="nav" aria-selected="false" data-tab="traffic">Traffic</button>
</aside><main>
<div class="heading"><div><h1 id="heading">Overview</h1><div class="sub" id="stamp">Loading infrastructure status…</div></div><div class="toolbar" style="margin:0"><span id="live" class="live">Live updates</span><button class="btn" id="refresh">Refresh</button></div></div>
<div role="status" id="error" class="bad" aria-live="polite"></div>
<section class="section active" id="tab-overview"><div class="grid">
<div class="card"><div class="muted">OVH · FRPS connectivity</div><div class="value" id="upstream">—</div><div class="note">Evidence: registered FRPC proxy</div></div>
<div class="card"><div class="muted">Active tunnels</div><div class="value" id="active">—</div><div class="note">From local FRPC API</div></div>
<div class="card"><div class="muted">Monitoring</div><div class="value" id="monitoring">—</div><div class="note">Collector / FRPC status</div></div>
</div><div class="dashboard-lower">
<div class="card"><div class="flex-between"><h2>Active tunnels</h2><a href="#" id="all-tunnels">View all →</a></div><div class="scroll"><table><thead><tr><th>Proxy</th><th>Public endpoint</th><th>Target</th><th>Status</th></tr></thead><tbody id="overview-tunnels"></tbody></table></div></div>
<div class="card"><div class="flex-between"><h2>Security signals</h2><a href="#" id="all-security">View events →</a></div><div class="note" id="security-stamp">Fetching on a separate interval</div><ul class="mini-list" id="recent"><li class="muted">Waiting for events…</li></ul></div>
</div></section>
<section class="section" id="tab-tunnels"><div class="toolbar"><input id="tunnel-search" type="search" placeholder="Filter tunnels" aria-label="Filter tunnels"><span id="manage-links"></span></div><div class="card scroll"><table><thead><tr><th>Name</th><th>Protocol</th><th>Public endpoint</th><th>Local target</th><th>Proxy status</th><th>Action</th></tr></thead><tbody id="tunnel-rows"></tbody></table></div></section>
<section class="section" id="tab-health"><div class="card"><h2>Observed current states</h2><p class="note">Time below is measured only since the first recorded state transition; it is not guaranteed service uptime.</p><div class="grid" id="health-current" style="margin-bottom:20px"></div><h2>Availability timeline</h2><ol id="health-timeline" class="healthline"></ol><h2>State changes</h2><p class="note">Samples every 30 seconds; only transitions are recorded. A running UDP proxy does not prove the game server responds.</p><div class="scroll"><table><thead><tr><th>Time (UTC)</th><th>Component</th><th>Previous</th><th>Current</th></tr></thead><tbody id="health-rows"></tbody></table></div></div></section>
<section class="section" id="tab-history"><div class="card"><div class="flex-between"><h2>Configuration history</h2><a href="/history">Full audit and changes →</a></div><div id="version-list">Loading history…</div><h2>Compare versions</h2><div class="toolbar"><select id="diff-before" aria-label="Earlier version"></select><select id="diff-after" aria-label="Later version"></select><button type="button" class="btn" id="show-diff">Compare</button></div><div id="version-diff" class="review-list"></div><p class="note">Restore remains disabled pending tests. Sensitive configuration values are not displayed.</p></div></section>
<section class="section" id="tab-security"><div class="toolbar"><select id="time-filter" aria-label="Time range"><option value="24">Last 24 hours</option><option value="12">Last 12 hours</option><option value="6">Last 6 hours</option><option value="1">Last hour</option></select><select id="severity" aria-label="Filter by severity"><option value="">All severities</option><option value="high">High</option><option value="warning">Warning</option><option value="info">Info</option></select><input type="search" id="security-search" placeholder="Filter events or address" aria-label="Search security events"><span class="note">FRPS journal · maximum 24h · aggregated</span><select id="page-size" aria-label="Rows per page"><option value="20">20 rows</option><option value="50">50 rows</option><option value="100">100 rows</option></select></div><div class="card scroll"><table><thead><tr><th>Time (UTC)</th><th>Severity</th><th>Category</th><th>Details</th><th>Count</th></tr></thead><tbody id="security-rows"></tbody></table></div><div class="toolbar" style="justify-content:flex-end;margin-top:12px"><span id="security-total" class="note"></span><button type="button" id="prev-page" class="btn">Previous</button><span id="security-page" class="note"></span><button type="button" id="next-page" class="btn">Next</button></div></section><dialog id="tunnel-modal" aria-labelledby="tunnel-modal-title"><div class="flex-between"><h2 id="tunnel-modal-title">Tunnel</h2><button type="button" class="btn" id="close-tunnel-modal">Close</button></div>
<p id="tunnel-description" class="note">Validate changes before applying them to FRPC.</p>
<form id="tunnel-form">
<label>Name<input id="form-name" maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,63}" required></label>
<label>Protocol<select id="form-protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
<div class="form-cols"><label>Local IPv4<input id="form-ip" required placeholder="192.168.1.37"></label><label>Local port<input id="form-localport" type="number" min="1" max="65535" required></label></div>
<label>Public port<input id="form-publicport" type="number" min="1" max="65535" required></label>
<div class="modal-actions"><button type="button" class="btn danger" id="form-delete" hidden>Delete tunnel</button><button type="submit" class="btn" id="form-preview">Validate &amp; preview</button></div>
</form>
<div id="tunnel-metadata" class="card" hidden><h2>Label &amp; maintenance</h2><p class="note">UI-only metadata. Does not edit FRPC settings or disable your tunnel.</p><label>Description<textarea id="meta-description" maxlength="240" rows="2" placeholder="What runs behind this tunnel?"></textarea></label><label>Tags (comma-separated)<input id="meta-tags" maxlength="200" placeholder="Games, Production"></label><label>Maintenance ends (optional)<input id="meta-until" type="datetime-local"></label><div class="modal-actions"><button type="button" class="btn" id="save-meta">Save labels</button></div></div>
<div id="tunnel-preview" hidden><h2>Review changes</h2><div id="tunnel-diff" class="review-list"></div><div id="tunnel-confirm-line" hidden><label>Type tunnel name to confirm deletion<input id="tunnel-confirm-name" autocomplete="off"></label></div><div class="modal-actions"><button class="btn" type="button" id="preview-back">Back</button><button class="btn" type="button" id="form-apply">Apply operation</button></div></div>
<p id="tunnel-feedback" role="status" aria-live="polite"></p>
</dialog>
<dialog id="incident" aria-labelledby="incident-title"><div class="flex-between"><h2 id="incident-title">Event details</h2><button type="button" class="btn" id="close-incident">Close</button></div><div id="incident-body"></div><p class="note">These are sanitized FRPS events, not evidence of individual user activity inside a tunnel.</p></dialog>
<section class="section" id="tab-diagnostics"><div class="card"><h2>Security and diagnostics</h2><p class="note">Read-only checks. Remote OVH settings are not inspected.</p><div id="diag-list"></div></div></section>
<section class="section" id="tab-traffic"><div class="card"><h2>FRPS traffic and connections</h2><p class="note">Counters supplied by the authenticated FRPS dashboard API when explicitly enabled on OVH. No usage is estimated.</p><div id="traffic-list">Loading…</div></div></section>
<section class="section" id="tab-backup"><div class="card"><h2>Configuration snapshots &amp; recovery readiness</h2><p class="note">Audited snapshots are not independent disaster-recovery backups. Exported manifest contains only previously redacted change metadata, not credentials or a restorable FRPC configuration.</p><div id="backup-status">Loading…</div><div class="toolbar"><button type="button" class="btn" id="download-manifest">Export sanitized history manifest</button></div><p class="note">Restoring configurations requires separate tested root-owned backup procedures. FRP Manager does not automatically turn on restore.</p></div></section>
<section class="section" id="tab-alerts"><div class="card"><h2>Notification worker</h2><p class="note">Opt-in outbound webhook alerting. Configure the worker on the LXC via a root-only environment file; no webhook secret is ever shown here.</p><div id="alerts-status">Loading…</div></div></section>
<section class="section" id="tab-topology"><div class="card"><h2>Connection topology</h2><p class="note">Logical route. A registered proxy does not prove an application is responding.</p><div id="topology-list"></div></div></section>
</main></div>
<script>
"use strict";
const $=id=>document.getElementById(id);let tab="overview",tunnels=[],tunnelMeta={},security=[],securityPage=0,allowManage=__CAN_MANAGE__,allowCreate=__CAN_CREATE__,loading=false,loadQueued=false;
const title={overview:"Overview",tunnels:"Tunnels",health:"Health",history:"History",security:"Security Events",diagnostics:"Diagnostics",topology:"Topology",alerts:"Alerts",backup:"Backup & Recovery",traffic:"Traffic"};
function cell(row,value){const td=document.createElement("td");td.textContent=String(value??"—");row.append(td);return td}
function stateClass(v){const x=String(v||"unknown").toLowerCase();return ["running","available","connected","success"].includes(x)?"ok":["error","failed","stopped","closed","disconnected","offline"].includes(x)?"fail":"unknown"}
function stateCell(row,v){const td=document.createElement("td"),span=document.createElement("span");span.className="state "+stateClass(v);span.textContent=status(v);td.append(span);row.append(td)}
function status(value){return value===null||value===undefined?"Unknown":String(value)}
function fmt(date){if(!date)return"—";const d=new Date(date);return Number.isNaN(d.getTime())?"—":d.toISOString().replace("T"," ").slice(0,19)}
async function api(url){const c=new AbortController();const timer=setTimeout(()=>c.abort(),30000);try{const res=await fetch(url,{signal:c.signal,cache:"no-store"});if(res.status===401){location.assign("/login");throw Error("Authentication required")}if(!res.ok)throw Error("HTTP "+res.status);return await res.json()}finally{clearTimeout(timer)}}
function empty(body,msg){const tr=document.createElement("tr");const td=document.createElement("td");td.colSpan=6;td.className="empty";td.textContent=msg;tr.append(td);body.append(tr)}
let historyVersions=[];
function compareVersions(){const before=Number($("diff-before").value),after=Number($("diff-after").value),container=$("version-diff");container.replaceChildren();if(before===after){container.textContent="Select two different versions";return}const snapshots=new Map(),state={};for(const ver of historyVersions.slice().sort((a,b)=>a.id-b.id)){for(const patch of ver.changes||[]){if(patch.after==null)delete state[patch.name];else state[patch.name]=patch.after}snapshots.set(ver.id,JSON.parse(JSON.stringify(state)))}const a=snapshots.get(before)||{},b=snapshots.get(after)||{};for(const name of new Set([...Object.keys(a),...Object.keys(b)])){const left=JSON.stringify(a[name]??null),right=JSON.stringify(b[name]??null);if(left===right)continue;const div=document.createElement("div"),h=document.createElement("strong"),x=document.createElement("pre");h.textContent=name;x.textContent="v"+before+": "+left+String.fromCharCode(10)+"v"+after+": "+right;div.append(h,x);container.append(div)}if(!container.children.length)container.textContent="No differences found in available audited change metadata"}
$("show-diff").addEventListener("click",compareVersions);
$("download-manifest").addEventListener("click",async()=>{try{const data=await api("/api/history");const manifest={type:"redacted-history-manifest",restorable:false,generated_at:new Date().toISOString(),versions:data.versions||[],operations:data.operations||[]};const blob=new Blob([JSON.stringify(manifest,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="frp-manager-audit-manifest.json";link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}catch(e){$("error").textContent="Unable to download sanitized manifest: "+e.message}});
let tunnelMode="add",originalTunnel=null,tunnelCsrf="",tunnelPreview=null,tunnelAction="",tunnelBusy=false;
let tunnelMetaCsrf="";
const getForm=()=>({name:$("form-name").value.trim(),protocol:$("form-protocol").value,local_ip:$("form-ip").value.trim(),local_port:Number($("form-localport").value),public_port:Number($("form-publicport").value)});
function setTunnelFeedback(text,isError=false){$("tunnel-feedback").textContent=text;$("tunnel-feedback").className=isError?"bad":"note"}
function addReview(title,before,after){const div=document.createElement("div"),label=document.createElement("strong"),span=document.createElement("span");label.textContent=title;span.textContent=before===undefined?String(after):String(before)+"  →  "+String(after);span.className=before!==undefined&&before!==after?"changed":"current";div.append(label,span);$("tunnel-diff").append(div)}
function showTunnelReview(action,values){tunnelAction=action;tunnelPreview=values;$("tunnel-diff").replaceChildren();if(action==="delete"){for(const [k,v] of Object.entries(originalTunnel))addReview(k,undefined,v)}else{for(const [k,v] of Object.entries(values)){addReview(k,originalTunnel?originalTunnel[k]:undefined,v)}}$("tunnel-form").hidden=true;$("tunnel-preview").hidden=false;$("tunnel-confirm-line").hidden=action!=="delete";$("tunnel-confirm-name").value="";$("form-apply").disabled=action==="delete"||!tunnelCanWrite;$("form-apply").textContent=action==="delete"?"Confirm deletion":action==="edit"?"Apply changes":"Create tunnel";if(!tunnelCanWrite)setTunnelFeedback("Preview only: tunnel write operations are disabled on this host.");else setTunnelFeedback("Review carefully: applying changes may restart FRPC.")}
let tunnelCanWrite=false;
async function openTunnelModal(path,label){if($("tunnel-modal").open)return;tunnelMode=path.startsWith("/tunnels/new")?"add":"edit";const name=tunnelMode==="edit"?new URL(path,location.origin).searchParams.get("name"):"";$("tunnel-modal-title").textContent=label;$("tunnel-form").hidden=false;$("tunnel-preview").hidden=true;$("tunnel-form").reset();$("form-delete").hidden=true;setTunnelFeedback("Loading tunnel settings…");$("tunnel-modal").showModal();try{const ctx=await api("/api/tunnels/form-context"+(name?"?name="+encodeURIComponent(name):""));if(!$("tunnel-modal").open)return;originalTunnel=ctx.tunnel;tunnelCsrf=tunnelMode==="add"?ctx.create_csrf:ctx.manage_csrf;tunnelCanWrite=tunnelMode==="add"?ctx.create_enabled:ctx.manage_enabled;tunnelMetaCsrf=ctx.meta_csrf;$("tunnel-metadata").hidden=!originalTunnel;$("meta-description").value=ctx.metadata?.description||"";$("meta-tags").value=(ctx.metadata?.tags||[]).join(", ");$("meta-until").value=ctx.metadata?.maintenance_until?ctx.metadata.maintenance_until.slice(0,16):"";if(originalTunnel){$("form-name").value=originalTunnel.name;$("form-protocol").value=originalTunnel.protocol;$("form-ip").value=originalTunnel.local_ip;$("form-localport").value=originalTunnel.local_port;$("form-publicport").value=originalTunnel.public_port;$("form-name").readOnly=true;$("form-protocol").disabled=true;$("form-delete").hidden=false}else{$("form-name").readOnly=false;$("form-protocol").disabled=false}$("tunnel-description").textContent=tunnelMode==="add"?"Create a new TCP or UDP proxy. Preview does not change running tunnels.":"Review edits or deletion before applying; every operation is audited.";setTunnelFeedback(tunnelCanWrite?"Ready to validate.":"Preview only: writing is currently disabled.")}catch(e){setTunnelFeedback("Could not load tunnel form: "+e.message,true);$("tunnel-form").hidden=true}}
function closeTunnelModal(){if(tunnelBusy)return;$("tunnel-modal").close()}
async function tunnelPost(url,payload){const r=await fetch(url,{method:"POST",credentials:"same-origin",cache:"no-store",headers:{"Content-Type":"application/json","X-CSRF-Token":tunnelCsrf},body:JSON.stringify(payload)});if(r.status===401){location.assign("/login");throw Error("Authentication required")}let response;try{response=await r.json()}catch{response={}}if(!r.ok)throw Error(response.detail||"HTTP "+r.status);return response}
$("tunnel-form").addEventListener("submit",async e=>{e.preventDefault();if(tunnelBusy)return;tunnelBusy=true;$("form-preview").disabled=true;setTunnelFeedback("Validating…");const values=getForm();try{if(tunnelMode==="add"){const response=await tunnelPost("/api/tunnels/preview",values);tunnelCanWrite=response.create_enabled;showTunnelReview("create",values)}else{const response=await tunnelPost("/api/tunnels/manage-preview",{action:"edit",name:originalTunnel.name,tunnel:values});showTunnelReview("edit",response.after||values)}}catch(err){setTunnelFeedback(err.message,true)}finally{tunnelBusy=false;$("form-preview").disabled=false}});
$("save-meta").addEventListener("click",async()=>{if(!originalTunnel||tunnelBusy)return;const desc=$("meta-description").value,tags=$("meta-tags").value.split(",").map(x=>x.trim()).filter(Boolean),until=$("meta-until").value;const payload={description:desc,tags,maintenance_until:until?new Date(until).toISOString():null};tunnelBusy=true;$("save-meta").disabled=true;setTunnelFeedback("Saving labels…");try{const r=await fetch("/api/tunnels/metadata/"+encodeURIComponent(originalTunnel.name),{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":tunnelMetaCsrf},body:JSON.stringify(payload)});const d=await r.json();if(!r.ok)throw Error(d.detail||"HTTP "+r.status);setTunnelFeedback("Labels and maintenance schedule saved. Tunnel traffic remains unchanged.");load()}catch(e){setTunnelFeedback(e.message,true)}finally{tunnelBusy=false;$("save-meta").disabled=false}});
$("form-delete").addEventListener("click",async()=>{if(tunnelBusy||!originalTunnel)return;tunnelBusy=true;setTunnelFeedback("Checking deletion…");try{await tunnelPost("/api/tunnels/manage-preview",{action:"delete",name:originalTunnel.name});showTunnelReview("delete",originalTunnel)}catch(e){setTunnelFeedback(e.message,true)}finally{tunnelBusy=false}});
$("tunnel-confirm-name").addEventListener("input",()=>{$("form-apply").disabled=!tunnelCanWrite||$("tunnel-confirm-name").value!==originalTunnel.name});
$("preview-back").addEventListener("click",()=>{$("tunnel-preview").hidden=true;$("tunnel-form").hidden=false;setTunnelFeedback("Preview discarded. No changes applied.")});
$("form-apply").addEventListener("click",async()=>{if(tunnelBusy||!tunnelCanWrite||!tunnelPreview)return;if(tunnelAction==="delete"&&$("tunnel-confirm-name").value!==originalTunnel.name)return;tunnelBusy=true;$("form-apply").disabled=true;setTunnelFeedback("Submitting operation…");try{const action=tunnelAction;const payload=action==="create"?tunnelPreview:action==="delete"?{action,name:originalTunnel.name}:{action,name:originalTunnel.name,tunnel:tunnelPreview};await tunnelPost(action==="create"?"/api/tunnels/create":"/api/tunnels/manage-apply",payload);setTunnelFeedback("Queued. Waiting for FRPC operation result…");let done=false;for(let i=0;i<45&&$("tunnel-modal").open;i++){await new Promise(resolve=>setTimeout(resolve,2000));const result=await api("/api/tunnels/create-status");if((result.state==="success"||result.state==="failed")&&result.name===payload.name&&(action==="create"||result.action===action)){done=true;if(result.state==="failed")throw Error(result.error||"Operation failed; check rollback status");setTunnelFeedback("Operation completed successfully.");load();break}}if(!done)setTunnelFeedback("Operation still processing. Review status before retrying.")}catch(err){setTunnelFeedback(err.message,true)}finally{tunnelBusy=false;$("form-apply").disabled=false}});
function namedTunnel(row,t){const td=cell(row,t.name),meta=tunnelMeta[t.name]||{};if((meta.tags||[]).length){const tags=document.createElement("span");tags.className="note";tags.style.marginLeft="8px";tags.textContent=meta.tags.join(", ");td.append(tags)}if(meta.maintenance_until&&Date.parse(meta.maintenance_until)>Date.now()){const badge=document.createElement("span");badge.className="signal warning";badge.style.marginLeft="8px";badge.textContent="Maintenance";td.append(badge)}return td}
function renderOverviewTunnels(){const body=$("overview-tunnels");body.replaceChildren();for(const t of tunnels.slice(0,10)){const tr=document.createElement("tr");namedTunnel(tr,t);cell(tr,(t.public_ip||"—")+":"+(t.public_port??"—"));cell(tr,(t.local_ip||"—")+":"+(t.local_port??"—"));stateCell(tr,t.status);body.append(tr)}if(!tunnels.length)empty(body,"No configured tunnels")}
function renderRecent(){const list=$("recent");list.replaceChildren();const important=security.filter(e=>e.severity==="high"||e.severity==="warning").slice(0,5);if(!important.length){const li=document.createElement("li");li.textContent="No recent warning or high severity events";list.append(li);return}for(const e of important){const li=document.createElement("li"),label=document.createElement("span"),stamp=document.createElement("span");label.textContent=e.category.replaceAll("_"," ");label.className="signal "+e.severity;stamp.textContent=fmt(e.timestamp)+" UTC";stamp.className="note";li.append(label,stamp);list.append(li)}}
function renderTunnels(){const body=$("tunnel-rows");body.replaceChildren();const q=$("tunnel-search").value.toLowerCase();let shown=0;for(const t of tunnels){if(!JSON.stringify({t,meta:tunnelMeta[t.name]||{}}).toLowerCase().includes(q))continue;shown++;const tr=document.createElement("tr");namedTunnel(tr,t);cell(tr,String(t.protocol||"").toUpperCase());cell(tr,(t.public_ip||"—")+":"+(t.public_port??"—"));cell(tr,(t.local_ip||"—")+":"+(t.local_port??"—"));stateCell(tr,t.status);const td=cell(tr,"");if(allowManage){const probe=document.createElement("button");probe.className="btn";probe.type="button";probe.textContent="Test target";probe.style.marginRight="10px";probe.addEventListener("click",async()=>{probe.disabled=true;probe.textContent="Checking…";try{const result=await api("/api/health/target-check?name="+encodeURIComponent(t.name));probe.textContent=result.result;probe.title=result.detail}catch(e){probe.textContent="Check failed";probe.title=e.message}finally{setTimeout(()=>{probe.disabled=false;probe.textContent="Test target"},6000)}});td.append(probe);const link=document.createElement("a");link.href="/tunnels/manage?name="+encodeURIComponent(t.name);link.textContent="Manage";link.addEventListener("click",event=>{event.preventDefault();openTunnelModal(link.href,"Manage · "+t.name)});td.append(link)}body.append(tr)}if(!shown)empty(body,"No matching tunnels")}
let lastIncidentFocus=null;
function showIncident(event){const area=$("incident-body");area.replaceChildren();const dl=document.createElement("dl");for(const [key,val] of Object.entries({timestamp:fmt(event.timestamp)+" UTC",severity:event.severity,category:event.category,count:event.count,...(event.details||{})})){const dt=document.createElement("dt"),dd=document.createElement("dd");dt.className="muted";dt.textContent=key.replaceAll("_"," ");dd.textContent=String(val);dd.style.margin="0 0 10px";dl.append(dt,dd)}area.append(dl);lastIncidentFocus=document.activeElement;$("incident").showModal();$("close-incident").focus()}
function renderSecurity(){const body=$("security-rows");body.replaceChildren();const q=$("security-search").value.toLowerCase(),sev=$("severity").value,range=Number($("time-filter").value);const cutoff=Date.now()-range*3600000;const filtered=security.filter(e=>(!sev||e.severity===sev)&&(!q||JSON.stringify(e).toLowerCase().includes(q))&&new Date(e.timestamp).getTime()>=cutoff);const size=Number($("page-size").value),pages=Math.max(1,Math.ceil(filtered.length/size));securityPage=Math.min(securityPage,pages-1);const offset=securityPage*size;
for(const e of filtered.slice(offset,offset+size)){const tr=document.createElement("tr");cell(tr,fmt(e.timestamp));const level=cell(tr,e.severity);level.className="severity-"+e.severity;const td=document.createElement("td"),btn=document.createElement("button");btn.type="button";btn.className="event-link";btn.textContent=e.category.replaceAll("_"," ");btn.addEventListener("click",()=>showIncident(e));td.append(btn);tr.append(td);cell(tr,Object.entries(e.details||{}).map(([k,v])=>k+": "+v).join(", ")||"—");cell(tr,e.count);body.append(tr)}
if(!filtered.length)empty(body,"No matching security events");$("security-total").textContent=filtered.length+" groups";$("security-page").textContent=securityPage+1+" / "+pages;$("prev-page").disabled=securityPage===0;$("next-page").disabled=securityPage>=pages-1}

async function load(){if(loading){loadQueued=true;return}loading=true;$("refresh").disabled=true;$("error").textContent="";try{
if(tab==="overview"||tab==="tunnels"){const [d,m]=await Promise.all([api("/api/health/tunnels"),api("/api/tunnels/metadata")]);tunnels=d.tunnels||[];tunnelMeta=m.entries||{};renderTunnels();renderOverviewTunnels();$("active").textContent=tunnels.filter(t=>String(t.status).toLowerCase()==="running").length+" / "+tunnels.length;$("monitoring").textContent=d.monitoring||"Unknown"}
if(tab==="overview"){const d=await api("/api/health/overview");$("upstream").textContent=status(d.frps_connection);$("upstream").dataset.state=d.frps_connection;$("stamp").textContent="Last checked "+fmt(d.timestamp)+" UTC"}
if(tab==="health"){const d=await api("/api/health/history?limit=100");const body=$("health-rows");body.replaceChildren();$("health-timeline").replaceChildren();const cards=$("health-current");cards.replaceChildren();const sampled=new Date(d.sampled_at||0).getTime();const fresh=d.available&&Number.isFinite(sampled)&&Date.now()-sampled<120000;for(const state of d.states||[]){const box=document.createElement("div"),name=document.createElement("div"),value=document.createElement("div"),duration=document.createElement("div");box.className="card";name.className="note";value.className="state "+(fresh?stateClass(state.state):"unknown");duration.className="note";name.textContent=state.subject;value.textContent=fresh?state.state:"Unknown (stale sample)";const since=new Date(state.changed_at).getTime();duration.textContent=Number.isFinite(since)&&fresh?"Observed for "+Math.max(0,Math.floor((Date.now()-since)/60000))+" min":"Duration unknown";box.append(name,value,duration);cards.append(box)}for(const e of d.events||[]){const tr=document.createElement("tr");cell(tr,fmt(e.recorded_at));cell(tr,e.subject);cell(tr,e.previous);stateCell(tr,e.current);body.append(tr);if($("health-timeline").children.length<12){const li=document.createElement("li");li.className=stateClass(e.current);const label=document.createElement("span");label.textContent=fmt(e.recorded_at)+" UTC · "+e.subject;const val=document.createElement("span");val.textContent=status(e.current);li.append(label,val);$("health-timeline").append(li)}}if(!body.children.length)empty(body,"No health transitions recorded")}
if(tab==="security"){await pollSecurity();renderSecurity();}
if(tab==="traffic"){const data=await api("/api/metrics/traffic"),root=$("traffic-list");root.replaceChildren();if(!data.available){root.textContent=data.reason||"Remote metrics unavailable"}else{const table=document.createElement("table");const head=document.createElement("tr");for(const col of ["Tunnel","Connections","Today IN","Today OUT"]){const cell=document.createElement("th");cell.textContent=col;head.append(cell)}table.append(head);for(const p of data.proxies){const tr=document.createElement("tr");cell(tr,p.name);cell(tr,p.counters?.curConns??"Not reported");cell(tr,p.counters?.todayTrafficIn==null?"Not reported":(p.counters.todayTrafficIn/1024/1024).toFixed(2)+" MiB");cell(tr,p.counters?.todayTrafficOut==null?"Not reported":(p.counters.todayTrafficOut/1024/1024).toFixed(2)+" MiB");table.append(tr)}root.append(table);if(!data.proxies.length)root.textContent="No proxy counters reported"}}
if(tab==="backup"){const [history,archive]=await Promise.all([api("/api/history"),api("/api/backups/status")]);$("backup-status").textContent=(history.versions||[]).length+" audited versions · "+(archive.available?"last verified local archive: "+fmt(archive.last_created_at)+" UTC ("+archive.files+" files)":"no verified local archive reported")+". Offsite backup and restore have NOT been verified."}
if(tab==="alerts"){const d=await api("/api/alerts/status");$("alerts-status").textContent=d.configured?"Active · last check "+fmt(d.checked_at)+" UTC · "+d.monitored_subjects+" subjects":"Not configured or no successful check yet"}
if(tab==="diagnostics"){const data=await api("/api/diagnostics"),root=$("diag-list");root.replaceChildren();for(const c of data.checks){const row=document.createElement("div"),label=document.createElement("strong"),detail=document.createElement("p");row.style.padding="12px 0";row.style.borderBottom="1px solid var(--border)";label.textContent=c.name+" · "+c.result.toUpperCase();label.className=c.result==="passed"?"good":c.result==="failed"?"bad":"warn";detail.textContent=c.detail;row.append(label,detail);root.append(row)}const remote=await api("/api/diagnostics/remote");const h=document.createElement("h2");h.textContent="Remote OVH checks";root.append(h);if(!remote.available){const p=document.createElement("p");p.textContent=remote.reason;root.append(p)}else{for(const c of remote.checks){const el=document.createElement("p");el.textContent=c.name+" — "+c.result+": "+c.detail;el.className=c.result==="passed"?"good":"warn";root.append(el)}}}
if(tab==="topology"){const data=await api("/api/health/tunnels"),root=$("topology-list");root.replaceChildren();for(const t of data.tunnels||[]){const row=document.createElement("div");row.className="card";row.style.marginBottom="10px";const line=document.createElement("strong"),detail=document.createElement("div");line.textContent="Internet → OVH FRPS → FRPC → "+(t.local_ip||"local host");detail.className="note";detail.textContent=t.name+" · "+t.protocol+" · public :"+t.public_port+" → local :"+t.local_port+" · "+t.status;row.append(line,detail);root.append(row)}if(!root.children.length)root.textContent="No tunnels"}
if(tab==="history"){const d=await api("/api/history");historyVersions=d.versions||[];for(const id of ["diff-before","diff-after"]){const select=$(id);select.replaceChildren();for(const v of historyVersions){const option=document.createElement("option");option.value=v.id;option.textContent="v"+v.id;select.append(option)}}if(historyVersions.length>1){$("diff-before").value=historyVersions[0].id;$("diff-after").value=historyVersions[historyVersions.length-1].id}const list=$("version-list");list.replaceChildren();for(const v of (d.versions||[]).slice().reverse().slice(0,15)){const row=document.createElement("div");row.style.padding="11px 0";row.style.borderBottom="1px solid var(--border)";const heading=document.createElement("strong"),meta=document.createElement("div");heading.textContent="v"+v.id+" · "+v.summary;meta.className="note";meta.textContent=fmt(v.recorded_at)+" UTC · "+v.actor;row.append(heading,meta);list.append(row)}if(!list.children.length)list.textContent="No versions recorded";$("stamp").textContent="Configuration history · read-only"}
}catch(e){$("error").textContent="Unable to load "+title[tab]+": "+e.message}finally{loading=false;$("refresh").disabled=false;if(loadQueued){loadQueued=false;queueMicrotask(()=>load())}}}
function switchTab(next){tab=next;for(const b of document.querySelectorAll(".nav"))b.setAttribute("aria-selected",String(b.dataset.tab===next));for(const s of document.querySelectorAll(".section"))s.classList.toggle("active",s.id==="tab-"+next);$("heading").textContent=title[next];$("stamp").textContent="";load()}
for(const b of document.querySelectorAll(".nav"))b.addEventListener("click",()=>switchTab(b.dataset.tab));
$("refresh").addEventListener("click",load);$("tunnel-search").addEventListener("input",renderTunnels);for(const id of ["severity","time-filter","page-size"]){$(id).addEventListener("change",()=>{securityPage=0;renderSecurity()})}$("security-search").addEventListener("input",()=>{securityPage=0;renderSecurity()});$("prev-page").addEventListener("click",()=>{securityPage--;renderSecurity()});$("next-page").addEventListener("click",()=>{securityPage++;renderSecurity()});$("close-tunnel-modal").addEventListener("click",closeTunnelModal);
$("tunnel-modal").addEventListener("close",()=>{load()});
$("tunnel-modal").addEventListener("click",e=>{if(e.target===$("tunnel-modal"))closeTunnelModal()});
$("close-incident").addEventListener("click",()=>{$("incident").close()});
$("incident").addEventListener("click",event=>{if(event.target===$("incident"))$("incident").close()});
$("incident").addEventListener("close",()=>{if(lastIncidentFocus?.isConnected)lastIncidentFocus.focus();lastIncidentFocus=null});
if(allowCreate){const add=document.createElement("button");add.className="btn";add.type="button";add.textContent="+ New tunnel";add.addEventListener("click",()=>openTunnelModal("/tunnels/new","Add tunnel"));$("manage-links").append(add)}
api("/api/me").then(u=>{$("who").textContent=u.name||"Signed in"}).catch(()=>{});
let lastOK=0,lastSecurity=0,securityBusy=false;
const initialLoad=load;
load=async function(){await initialLoad();if(!$("error").textContent){lastOK=Date.now();$("live").classList.remove("stale");$("live").textContent="Live · updated "+new Date().toLocaleTimeString()}else{$("live").classList.add("stale");$("live").textContent="Data may be stale"}};
async function pollSecurity(force=false){if(securityBusy||document.visibilityState!=="visible")return;if(!force&&Date.now()-lastSecurity<90000)return;securityBusy=true;try{const d=await api("/api/security/events");security=d.events||[];lastSecurity=Date.now();renderRecent();if(tab==="security")renderSecurity();$("security-stamp").textContent="FRPS journal · updated "+new Date().toLocaleTimeString()}catch(e){$("security-stamp").textContent="Security feed unavailable: "+e.message}finally{securityBusy=false}}
$("all-tunnels").addEventListener("click",e=>{e.preventDefault();switchTab("tunnels")});
$("all-security").addEventListener("click",e=>{e.preventDefault();switchTab("security")});
load();pollSecurity(true);
setInterval(()=>{if(!lastOK||document.visibilityState!=="visible")return;const age=Math.floor((Date.now()-lastOK)/1000);$("live").classList.toggle("stale",age>40);$("live").textContent=(age>40?"Stale":"Live")+" · "+age+"s ago"},1000);
setInterval(()=>{if(document.visibilityState==="visible"&&(tab==="overview"||tab==="tunnels"))load()},15000);
setInterval(()=>{if(document.visibilityState==="visible"&&(tab==="overview"||tab==="security"))pollSecurity()},30000);
setInterval(()=>{if(document.visibilityState==="visible"&&tab==="health")load()},30000);
document.addEventListener("visibilitychange",()=>{if(document.visibilityState==="visible"){if(tab==="overview"||tab==="tunnels")load();if(tab==="overview"||tab==="security")pollSecurity()}});
</script></body></html>
"""
    return HTMLResponse(page.replace("__CAN_MANAGE__", "true" if "frp-admin" in user["roles"] else "false").replace("__CAN_CREATE__", "true" if any(r in user["roles"] for r in ("frp-admin", "frp-operator")) else "false"),headers={"Cache-Control":"no-store"})


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
    check_public_port(protocol, public_port)
    return {
        "name": name,
        "type": protocol,
        "localIP": str(address),
        "localPort": local_port,
        "remotePort": public_port,
    }


@app.get("/api/tunnels/metadata")
async def tunnel_metadata(user=Depends(current_user)):
    names = {p.get("name") for p in read_config().get("proxies", [])}
    try:
        entries = ui_store.list_all()
    except (OSError, sqlite3.Error, RuntimeError):
        return {"enabled": False, "entries": {}}
    return {"enabled": True, "entries": {k: v for k,v in entries.items() if k in names}}


@app.post("/api/tunnels/metadata/{name}")
async def save_tunnel_metadata(name: str, request: Request, user=Depends(current_user)):
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403, "Administrator role required")
    if request.headers.get("origin") != PUBLIC_URL:
        raise HTTPException(403, "Invalid origin")
    token = request.session.get("tunnel_meta_csrf", "")
    if not token or not hmac.compare_digest(token, request.headers.get("x-csrf-token", "")):
        raise HTTPException(403, "Invalid CSRF token")
    if request.headers.get("content-type", "").split(";")[0].lower() != "application/json":
        raise HTTPException(415, "Expected JSON")
    if int(request.headers.get("content-length", "0") or "0") > 2048:
        raise HTTPException(413, "Request too large")
    if name not in {p.get("name") for p in read_config().get("proxies", [])}:
        raise HTTPException(404, "Tunnel not found")
    try:
        data = await request.json()
        if type(data) is not dict or set(data) != {"description", "tags", "maintenance_until"}:
            raise ValueError("Unexpected fields")
        result = ui_store.update(name, data["description"], data["tags"],
                                 data["maintenance_until"], user["sub"])
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except (OSError, sqlite3.Error, RuntimeError):
        raise HTTPException(503, "UI metadata storage unavailable") from None
    audit("tunnel_metadata", "success", subject=user["sub"])
    return result


@app.get("/api/tunnels/form-context")
async def tunnel_form_context(request: Request, name: str = "", user=Depends(current_user)):
    """Issue operation-scoped CSRF tokens and redacted tunnel form data."""
    if not any(role in user["roles"] for role in ("frp-admin", "frp-operator")):
        raise HTTPException(403, "Tunnel management role required")
    create_token = secrets.token_urlsafe(32)
    request.session["tunnel_preview_csrf"] = create_token
    request.session["tunnel_meta_csrf"] = secrets.token_urlsafe(32)
    response = {
        "create_csrf": create_token,
        "meta_csrf": request.session["tunnel_meta_csrf"],
        "manage_csrf": None,
        "create_enabled": "frp-admin" in user["roles"] and TUNNEL_ENABLED.is_file(),
        "manage_enabled": False,
        "tunnel": None
    }
    if name:
        if "frp-admin" not in user["roles"]:
            raise HTTPException(403, "Administrator role required")
        proxy = next((p for p in read_config().get("proxies", []) if p.get("name") == name), None)
        if proxy is None:
            raise HTTPException(404, "Tunnel not found")
        token = secrets.token_urlsafe(32)
        request.session["tunnel_manage_csrf"] = token
        response["manage_csrf"] = token
        response["manage_enabled"] = (TUNNEL_ENABLED.is_file() and TUNNEL_MANAGE_ENABLED.is_file())
        try:
            response["metadata"] = ui_store.read(name)
        except (OSError, sqlite3.Error, RuntimeError):
            response["metadata"] = None
        response["tunnel"] = {
            "name": proxy["name"], "protocol": proxy["type"],
            "local_ip": proxy.get("localIP"),
            "local_port": proxy.get("localPort"),
            "public_port": proxy.get("remotePort")
        }
    return JSONResponse(response, headers={"Cache-Control": "no-store"})


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
body{background:#0d1117!important;color:#eef2f8!important;font-family:system-ui,-apple-system,"Segoe UI",sans-serif!important;line-height:1.55!important}
a{color:#92b9ff!important}a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid #92b9ff;outline-offset:3px}
h1{font-size:28px;letter-spacing:-.025em}h2{font-size:19px}
input,select,textarea{background:#121a25!important;border:1px solid #3a4556!important;color:#eef2f8!important;border-radius:8px!important;padding:10px!important}
button{background:#2c3c56;color:#fff;border:1px solid #4b5b71;border-radius:8px;padding:10px 14px;cursor:pointer}
button:hover{background:#3a4c69}button:disabled{opacity:.45;cursor:not-allowed}
article,pre,details{border-color:#30394a!important}pre{background:#151e2b!important;color:#dce6f5!important;overflow:auto}
.confirm-dialog{background:#182232;color:#eef2f8;border:1px solid #53627b;border-radius:14px;padding:24px;width:min(440px,calc(100vw - 28px));box-shadow:0 24px 70px #000a}
.confirm-dialog::backdrop{background:#050911d9}.confirm-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}
.confirm-dialog input{width:100%}.confirm-dialog h2{margin-top:0}.confirm-dialog .danger{background:#76313b;color:#fff}
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
<dialog class="confirm-dialog" id="custom-confirm" aria-labelledby="confirm-title"><h2 id="confirm-title">Confirm operation</h2><p id="confirm-question"></p><label id="confirm-label" hidden>Type the tunnel name<input id="confirm-name" autocomplete="off"></label><div class="confirm-actions"><button type="button" id="confirm-cancel">Cancel</button><button type="button" id="confirm-accept">Continue</button></div></dialog>
<script>
function customConfirm(message,expectedName=""){return new Promise(resolve=>{const modal=document.getElementById("custom-confirm"),input=document.getElementById("confirm-name"),label=document.getElementById("confirm-label"),accept=document.getElementById("confirm-accept");document.getElementById("confirm-question").textContent=message;input.value="";label.hidden=!expectedName;accept.disabled=!!expectedName;accept.classList.toggle("danger",!!expectedName);function changed(){accept.disabled=!!expectedName&&input.value!==expectedName}function done(ok){input.removeEventListener("input",changed);accept.removeEventListener("click",yes);cancel.removeEventListener("click",no);modal.removeEventListener("cancel",esc);if(modal.open)modal.close();resolve(ok)}function yes(){done(true)}function no(){done(false)}function esc(){done(false)}const cancel=document.getElementById("confirm-cancel");input.addEventListener("input",changed);accept.addEventListener("click",yes);cancel.addEventListener("click",no);modal.addEventListener("cancel",esc,{once:true});modal.showModal();(expectedName?input:cancel).focus()})}

const csrf="__TOKEN__";
document.getElementById("form").addEventListener("submit",async e=>{
 e.preventDefault();const feedback=document.getElementById("feedback");
 const preview=document.getElementById("preview");preview.hidden=true;document.getElementById("create").hidden=true;feedback.textContent="Validating...";
 const value=id=>document.getElementById(id).value;
 const body={name:value("name"),protocol:value("protocol"),local_ip:value("local_ip"),
 local_port:Number(value("local_port")),public_port:Number(value("public_port"))};
 try{
  const r=await fetch("/api/tunnels/preview",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body)});
  if(r.status===401){window.location.assign("/login");return;}
 const data=await r.json();
  if(!r.ok){feedback.className="error";feedback.textContent=data.detail||"Validation failed";return;}
  feedback.className="";feedback.textContent="Validation passed. Preview generated; no tunnel has been created.";
  preview.hidden=false;preview.textContent=data.toml_preview;
  document.getElementById("create").hidden=!data.create_enabled;
 }catch(err){feedback.className="error";feedback.textContent="Unable to validate tunnel."}
});
document.getElementById("create").addEventListener("click",async()=>{
 if(!await customConfirm("Create this tunnel and restart FRPC? Existing tunnels will be checked."))return;
 const value=id=>document.getElementById(id).value;
 const body={name:value("name"),protocol:value("protocol"),local_ip:value("local_ip"),
 local_port:Number(value("local_port")),public_port:Number(value("public_port"))};
 const r=await fetch("/api/tunnels/create",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(body)});
 const result=document.getElementById("result");
 result.textContent=r.ok?"Creation queued. Check result below in a few seconds.":JSON.stringify(await r.json());
 if(r.ok){
 document.getElementById("create").hidden=true;
 const started=Date.now();
 const timer=setInterval(async()=>{
  try{
   const res=await fetch("/api/tunnels/create-status",{cache:"no-store"});
   if(res.status===401){clearInterval(timer);window.location.assign("/login");return;}
   if(!res.ok)return;
   const data=await res.json();
   if(data.state==="success"||data.state==="failed"){
    clearInterval(timer);
    result.textContent=data.state==="success"?"Tunnel created successfully.":("Tunnel creation failed: "+(data.error||"Unknown reason")+(data.rollback_failed?" (rollback failed)":" (previous configuration restored if rollback succeeded)"));
   }else if(Date.now()-started>90000){clearInterval(timer);result.textContent="Operation is still pending. Check status later.";}
  }catch(e){if(Date.now()-started>90000)clearInterval(timer);}
 },2000);
}
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
        "actor": {"sub": user["sub"], "name": user["name"]},
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
        return {k: record[k] for k in ("state", "name", "protocol", "action", "updated_at", "error", "rollback_failed") if k in record}
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
button{cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}body{background:#0d1117!important;color:#eef2f8!important;font-family:system-ui,-apple-system,"Segoe UI",sans-serif!important;line-height:1.55!important}
a{color:#92b9ff!important}a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid #92b9ff;outline-offset:3px}
h1{font-size:28px;letter-spacing:-.025em}h2{font-size:19px}
input,select,textarea{background:#121a25!important;border:1px solid #3a4556!important;color:#eef2f8!important;border-radius:8px!important;padding:10px!important}
button{background:#2c3c56;color:#fff;border:1px solid #4b5b71;border-radius:8px;padding:10px 14px;cursor:pointer}
button:hover{background:#3a4c69}button:disabled{opacity:.45;cursor:not-allowed}
article,pre,details{border-color:#30394a!important}pre{background:#151e2b!important;color:#dce6f5!important;overflow:auto}
.confirm-dialog{background:#182232;color:#eef2f8;border:1px solid #53627b;border-radius:14px;padding:24px;width:min(440px,calc(100vw - 28px));box-shadow:0 24px 70px #000a}
.confirm-dialog::backdrop{background:#050911d9}.confirm-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}
.confirm-dialog input{width:100%}.confirm-dialog h2{margin-top:0}.confirm-dialog .danger{background:#76313b;color:#fff}
</style></head>
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
<dialog class="confirm-dialog" id="custom-confirm" aria-labelledby="confirm-title"><h2 id="confirm-title">Confirm operation</h2><p id="confirm-question"></p><label id="confirm-label" hidden>Type the tunnel name<input id="confirm-name" autocomplete="off"></label><div class="confirm-actions"><button type="button" id="confirm-cancel">Cancel</button><button type="button" id="confirm-accept">Continue</button></div></dialog>
<script>
function customConfirm(message,expectedName=""){return new Promise(resolve=>{const modal=document.getElementById("custom-confirm"),input=document.getElementById("confirm-name"),label=document.getElementById("confirm-label"),accept=document.getElementById("confirm-accept");document.getElementById("confirm-question").textContent=message;input.value="";label.hidden=!expectedName;accept.disabled=!!expectedName;accept.classList.toggle("danger",!!expectedName);function changed(){accept.disabled=!!expectedName&&input.value!==expectedName}function done(ok){input.removeEventListener("input",changed);accept.removeEventListener("click",yes);cancel.removeEventListener("click",no);modal.removeEventListener("cancel",esc);if(modal.open)modal.close();resolve(ok)}function yes(){done(true)}function no(){done(false)}function esc(){done(false)}const cancel=document.getElementById("confirm-cancel");input.addEventListener("input",changed);accept.addEventListener("click",yes);cancel.addEventListener("click",no);modal.addEventListener("cancel",esc,{once:true});modal.showModal();(expectedName?input:cancel).focus()})}

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
if(r.status===401){window.location.assign("/login");return;}
 const d=await r.json();document.getElementById("result").textContent=r.ok?"Edit validation passed. No changes made.":d.detail;
 if(r.ok)showApply({action:"edit",name:original.name,tunnel:d.after});else{pending=null;document.getElementById("apply").hidden=true;}
document.getElementById("preview").textContent=r.ok?JSON.stringify(d,null,2):"";
});
document.getElementById("delete").addEventListener("click",async()=>{
 if(!await customConfirm("Preview deletion of tunnel "+original.name+"? Enter the exact tunnel name.",original.name))return;
 const r=await fetch("/api/tunnels/manage-preview",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":"__TOKEN__"},body:JSON.stringify({action:"delete",name:original.name})});
 if(r.status===401){window.location.assign("/login");return;}
 const d=await r.json();document.getElementById("result").textContent=r.ok?"Delete preview ready. No changes made.":d.detail;
 if(r.ok)showApply({action:"delete",name:original.name});else{pending=null;document.getElementById("apply").hidden=true;}
 document.getElementById("preview").textContent=r.ok?JSON.stringify(d,null,2):"";
});
document.getElementById("apply").addEventListener("click",async()=>{
 if(!pending)return;
 const action=pending.action;
 if(action==="delete" && !await customConfirm("Confirm permanent removal of "+original.name+". Enter the exact tunnel name.",original.name))return;
 if(!await customConfirm((action==="delete"?"Delete":"Edit")+" tunnel "+original.name+" and restart FRPC?"))return;
 const r=await fetch("/api/tunnels/manage-apply",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":"__TOKEN__"},body:JSON.stringify(pending)});
 if(r.status===401){window.location.assign("/login");return;}
 const data=await r.json();
 document.getElementById("result").textContent=r.ok?"Operation queued. Check the status in a moment.":(data.detail||"Request failed");
 if(r.ok){
  document.getElementById("apply").hidden=true;pending=null;
  const started=Date.now(),result=document.getElementById("result");
  const timer=setInterval(async()=>{
    try{
      const res=await fetch("/api/tunnels/create-status",{cache:"no-store"});
      if(res.status===401){clearInterval(timer);window.location.assign("/login");return;}
      if(!res.ok)return;
      const info=await res.json();
      if((info.state==="success"||info.state==="failed") && info.action===action && info.name===original.name){
        clearInterval(timer);
        result.textContent=info.state==="success"?"Operation completed successfully.":("Operation failed: "+(info.error||"Unknown reason")+(info.rollback_failed?" (rollback failed)":" (rollback requested if configuration was changed)"));
      } else if(Date.now()-started>90000){clearInterval(timer);result.textContent="Still processing. Check operation status later.";}
    }catch(err){if(Date.now()-started>90000)clearInterval(timer);}
  },2000);
}
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
    check_public_port(candidate["protocol"], candidate["public_port"])
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
        check_public_port(candidate["protocol"],candidate["public_port"])
    elif set(payload)!={"action","name"}:
        raise HTTPException(422,"Invalid request fields")
    if TUNNEL_REQUEST.exists():
        raise HTTPException(409,"Another tunnel operation is queued")
    payload["actor"] = {"sub": user["sub"], "name": user["name"]}
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


HISTORY_PUBLIC = Path("/var/lib/frp-manager/history-public.json")


def load_public_history():
    try:
        data = json.loads(HISTORY_PUBLIC.read_text(encoding="utf-8"))
        if type(data) is not dict or type(data.get("versions")) is not list:
            raise ValueError("Invalid history metadata")
        return data
    except FileNotFoundError:
        raise HTTPException(503, "History is not initialized")
    except (OSError, ValueError):
        raise HTTPException(503, "History metadata unavailable")


@app.get("/api/history")
async def history_api(user=Depends(current_user)):
    return load_public_history()


@app.get("/history", response_class=HTMLResponse)
async def history_page(user=Depends(current_user)):
    html = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Configuration history - FRP Manager</title>
<style>:root{color-scheme:dark;font:16px system-ui;background:#15181c;color:#e9ecef}
body{max-width:980px;margin:40px auto;padding:0 20px}a{color:#b3d5ff}
article{border:1px solid #343b42;border-radius:8px;padding:18px;margin:12px 0}
small{color:#aeb6bf}details{margin-top:12px}pre{white-space:pre-wrap;overflow-wrap:anywhere}
.before{color:#ffb5b5}.after{color:#99e5b1}
body{background:#0d1117!important;color:#eef2f8!important;font-family:system-ui,-apple-system,"Segoe UI",sans-serif!important;line-height:1.55!important}
a{color:#92b9ff!important}a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid #92b9ff;outline-offset:3px}
h1{font-size:28px;letter-spacing:-.025em}h2{font-size:19px}
input,select,textarea{background:#121a25!important;border:1px solid #3a4556!important;color:#eef2f8!important;border-radius:8px!important;padding:10px!important}
button{background:#2c3c56;color:#fff;border:1px solid #4b5b71;border-radius:8px;padding:10px 14px;cursor:pointer}
button:hover{background:#3a4c69}button:disabled{opacity:.45;cursor:not-allowed}
article,pre,details{border-color:#30394a!important}pre{background:#151e2b!important;color:#dce6f5!important;overflow:auto}
</style></head><body>
<a href="/">← Back to tunnels</a><h1>Configuration history</h1>
<p>Read-only snapshots. Configuration credentials are never displayed. Restore is not enabled.</p>
<div id="records">Loading history...</div><h2>Recent operations</h2><div id="operations"></div>
<script>
async function load(){
const target=document.getElementById("records");
try{
 const response=await fetch("/api/history",{cache:"no-store"});
 if(response.status===401){window.location.assign("/login");return;}
 if(!response.ok)throw Error("HTTP "+response.status);
 const body=await response.json();target.replaceChildren();
 for(const item of body.versions){
  const article=document.createElement("article");
  const title=document.createElement("strong");
  title.textContent="v"+item.id+" · "+item.summary;
  article.append(title);
  const meta=document.createElement("p"),small=document.createElement("small");
  small.textContent=item.recorded_at+" · "+item.actor+" · SHA256 "+item.sha256.slice(0,12);
  meta.append(small);article.append(meta);
  const details=document.createElement("details"),summary=document.createElement("summary");
  summary.textContent="View changes ("+item.changes.length+")";details.append(summary);
  for(const change of item.changes){
   const name=document.createElement("p");name.textContent=change.name;details.append(name);
   for(const side of ["before","after"]){
    const pre=document.createElement("pre");
    pre.className=side;
    pre.textContent=side+": "+JSON.stringify(change[side],null,2);
    details.append(pre);
   }
  }
  article.append(details);target.append(article);
 }
 if(!body.versions.length)target.textContent="No snapshots available.";
 const operations=document.getElementById("operations");
 operations.replaceChildren();
 for(const event of (body.operations||[])){
   const line=document.createElement("article");
   const heading=document.createElement("strong");
   heading.textContent=(event.outcome==="success"?"SUCCESS":"FAILED")+" · "+event.action+" · "+(event.tunnel||"unknown");
   const meta=document.createElement("p"),label=document.createElement("small");
   label.textContent=event.recorded_at+" · "+event.actor;
   meta.append(label);line.append(heading,meta);
   if(event.error){const error=document.createElement("p");error.textContent=event.error;line.append(error);}
   if(event.rollback_failed){const alert=document.createElement("strong");alert.textContent="ROLLBACK FAILED - inspect FRPC immediately";line.append(alert);}
   operations.append(line);
 }
 if(!(body.operations||[]).length)operations.textContent="No recorded operations yet.";
}catch(err){target.textContent="Unable to load history: "+err.message;}
}
load();
</script></body></html>"""
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})

RESTORE_ENABLED = Path("/etc/frp-manager/tunnel-restore-enabled")

@app.get("/api/history/restore-preview/{version}")
async def restore_preview(version: int, user=Depends(current_user)):
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403, "Administrator required")
    data = load_public_history()
    entry = next((row for row in data["versions"] if row["id"] == version), None)
    if entry is None:
        raise HTTPException(404, "Version not found in recent history")
    live = Path("/etc/frp/frpc.toml")
    try:
        digest = hashlib.sha256(live.read_bytes()).hexdigest()
    except OSError:
        raise HTTPException(503, "Configuration unavailable")
    latest = data["versions"][0] if data["versions"] else None
    if not latest or latest["sha256"] != digest:
        raise HTTPException(409, "Live configuration differs from recorded history")
    if digest == entry["sha256"]:
        raise HTTPException(409, "Requested version is already active")
    return {"version": version, "expected_sha256": digest,
            "target_sha256": entry["sha256"], "summary": entry["summary"],
            "changes": entry["changes"], "enabled": RESTORE_ENABLED.is_file(),
            "note": "Restore will create a new version and restart FRPC"}

@app.post("/api/history/restore")
async def restore_submit(request: Request, user=Depends(current_user)):
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403, "Administrator required")
    if not RESTORE_ENABLED.is_file() or not TUNNEL_ENABLED.is_file():
        raise HTTPException(503, "Restore is disabled")
    if request.headers.get("origin") != PUBLIC_URL:
        raise HTTPException(403, "Invalid origin")
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "Expected JSON")
    if int(request.headers.get("content-length", "0") or "0") > 4096:
        raise HTTPException(413, "Request too large")
    expected = request.session.get("tunnel_restore_csrf", "")
    token = request.headers.get("x-csrf-token", "")
    if not expected or not hmac.compare_digest(expected, token):
        raise HTTPException(403, "Invalid CSRF token")
    try:
        data = await request.json()
    except ValueError:
        raise HTTPException(422, "Invalid JSON")
    if type(data) is not dict or set(data) != {"version", "expected_sha256"}:
        raise HTTPException(422, "Invalid fields")
    version = data["version"]
    if type(version) is not int or version < 1:
        raise HTTPException(422, "Invalid version")
    preview = await restore_preview(version, user)
    if preview["expected_sha256"] != data["expected_sha256"]:
        raise HTTPException(409, "Configuration changed since preview")
    payload = {"action": "restore", "version": version,
               "expected_sha256": preview["expected_sha256"],
               "actor": {"sub": user["sub"], "name": user["name"]}}
    fd, tmp = tempfile.mkstemp(prefix=".tunnel-restore-", dir=TUNNEL_REQUEST.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        try:
            os.link(tmp, TUNNEL_REQUEST)
        except FileExistsError:
            raise HTTPException(409, "Another operation is queued")
    finally:
        os.unlink(tmp)
    return JSONResponse({"state": "queued", "action": "restore", "version": version}, status_code=202)

@app.get("/api/history/restore-csrf")
async def restore_csrf(request: Request, user=Depends(current_user)):
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403, "Administrator required")
    token = secrets.token_urlsafe(32)
    request.session["tunnel_restore_csrf"] = token
    return {"csrf": token, "enabled": RESTORE_ENABLED.is_file()}

HEALTH_PUBLIC = Path("/var/lib/frp-manager/health-public.json")


def read_health_events(limit=100):
    if not HEALTH_PUBLIC.is_file():
        return {"available": False, "states": [], "events": []}
    try:
        with HEALTH_PUBLIC.open(encoding="utf-8") as stream:
            data=json.load(stream)
        if not isinstance(data,dict) or not isinstance(data.get("events"),list):
            raise ValueError("Invalid health export")
        return {"available":True,"sampled_at":data.get("sampled_at"),
                "states":data.get("states",[]),"events":data["events"][:min(500,max(1,limit))]}
    except (OSError,ValueError):
        raise HTTPException(503,"Health export unavailable")


@app.get("/api/health/target-check")
async def target_check(name: str, user=Depends(current_user)):
    """Opt-in bounded TCP target probe for preconfigured tunnels only."""
    import socket
    if "frp-admin" not in user["roles"]:
        raise HTTPException(403, "Administrator role required")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
        raise HTTPException(422, "Invalid tunnel name")
    proxy = next((p for p in read_config().get("proxies", []) if p.get("name") == name), None)
    if proxy is None:
        raise HTTPException(404, "Tunnel not found")
    if proxy.get("type") != "tcp":
        return {"name": name, "result": "unsupported",
                "detail": "UDP requires protocol-specific probing; no packets were sent"}
    host, port = str(proxy.get("localIP", "")), proxy.get("localPort")
    try:
        ipaddress.IPv4Address(host)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid target port")
    except (ValueError, ipaddress.AddressValueError):
        return {"name": name, "result": "unknown", "detail": "Invalid configured endpoint"}
    def probe():
        try:
            with socket.create_connection((host, port), timeout=1.5):
                return "reachable"
        except (OSError, TimeoutError):
            return "unreachable"
    result = await asyncio.to_thread(probe)
    return {"name": name, "result": result,
            "detail": "TCP connect only from FRP Manager LXC to configured local target"}


@app.get("/api/diagnostics/remote")
async def remote_diagnostics(user=Depends(current_user)):
    try:
        return await asyncio.to_thread(get_frps_security)
    except (OSError,RuntimeError,ValueError,json.JSONDecodeError):
        return {"available":False,"checks":[],"reason":"Remote hardening helper not installed or unreachable"}


@app.get("/api/metrics/traffic")
async def traffic_metrics(user=Depends(current_user)):
    try:
        return await asyncio.to_thread(get_frps_metrics)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        return {"available":False,"reason":"OVH metric helper unavailable or not installed","proxies":[]}


@app.get("/api/backups/status")
async def backups_status(user=Depends(current_user)):
    path=Path("/var/lib/frp-manager/backup-public.json")
    try:
        item=json.loads(path.read_text(encoding="utf-8"))
        return {"available":bool(item.get("verified")),"scope":item.get("scope"),
                "last_created_at":item.get("created_at"),"files":item.get("files"),
                "local_only":True}
    except (OSError,ValueError):
        return {"available":False,"reason":"No verified local backup status; offsite backup not assessed"}


@app.get("/api/alerts/status")
async def alert_status(user=Depends(current_user)):
    path=Path("/var/lib/frp-manager/alert-status.json")
    try:
        with path.open(encoding="utf-8") as fd:
            record=json.load(fd)
        return {"configured": bool(record.get("enabled")),
                "checked_at": record.get("checked_at"),
                "monitored_subjects":record.get("monitored_subjects"),
                "alerts_sent_last_run":record.get("alerts_sent")}
    except (OSError,ValueError):
        return {"configured":False,"checked_at":None,"detail":"Alert worker has not reported a successful run"}


@app.get("/api/diagnostics")
async def diagnostics(user=Depends(current_user)):
    """Bounded read-only checks, no raw configuration or secrets."""
    from datetime import datetime, timezone
    from app import FRPC_CONFIG
    checks = []
    def add(name, result, detail):
        checks.append({"name": name, "result": result, "detail": detail})
    try:
        st = FRPC_CONFIG.stat()
        world = bool(st.st_mode & 0o007)
        add("FRPC configuration", "warning" if world else "passed",
            "World permissions present" if world else "Present; no world permissions")
    except OSError:
        add("FRPC configuration", "failed", "Configuration inaccessible")
    try:
        sample = read_health_events(1)
        stamp = datetime.fromisoformat(sample.get("sampled_at") or "")
        fresh = -30 < (datetime.now(timezone.utc) - stamp).total_seconds() < 120
        add("Health collector", "passed" if fresh else "warning",
            "Recent snapshot" if fresh else "Snapshot is stale")
        upstream = next((x.get("state") for x in sample["states"]
                         if x.get("subject") == "frps_connection"), "unknown")
        add("FRPS registration", "passed" if fresh and upstream == "connected" else "warning",
            "Proxy registered" if fresh and upstream == "connected" else "Registration not verified")
    except (HTTPException, ValueError, TypeError):
        add("Health collector", "warning", "Snapshot unavailable")
    try:
        config=read_config()
        method=config.get("auth",{}).get("method","token")
        add("FRPC authentication", "passed" if method in ("token","oidc") else "warning",
            "Authentication mechanism configured" if method in ("token","oidc") else "Authentication setting requires inspection")
        tls=config.get("transport",{}).get("tls",{}).get("enable", False)
        add("Client-to-server TLS", "passed" if tls is True else "warning",
            "FRPC TLS explicitly enabled" if tls is True else "TLS enablement not confirmed from client configuration")
        listen=str(config.get("webServer",{}).get("addr","127.0.0.1"))
        add("FRPC control API bind", "passed" if listen in ("127.0.0.1","::1","localhost") else "warning",
            "Loopback only" if listen in ("127.0.0.1","::1","localhost") else "Bound outside loopback; check firewall and authentication")
    except (OSError,ValueError,TypeError,KeyError):
        add("FRPC security settings", "warning", "Client config could not be safely assessed")
    add("Public port policy", "passed" if PORT_POLICY.is_file() and not PORT_POLICY.is_symlink() else "warning",
        "Local allowed-ports policy present" if PORT_POLICY.is_file() and not PORT_POLICY.is_symlink() else "Port policy missing or invalid")
    for name, path in (
        ("Tunnel writes", TUNNEL_ENABLED),
        ("Tunnel management", TUNNEL_MANAGE_ENABLED),
        ("Restore", Path("/etc/frp-manager/tunnel-restore-enabled"))
    ):
        enabled = path.is_file()
        add(name, "warning" if enabled else "passed",
            "Privilege-gated writes are enabled" if enabled else "Write operation disabled")
    return {"scope": "Local FRP Manager LXC only; no remote OVH audit", "checks": checks}


@app.get("/api/health/overview")
async def health_overview(user=Depends(current_user)):
    data = await asyncio.to_thread(get_tunnels)
    history = read_health_events(1)
    upstream = next((s["state"] for s in history["states"] if s["subject"]=="frps_connection"),"unknown")
    # A stopped collector must not leave a permanent false green connection.
    try:
        from datetime import datetime, timezone
        sampled=datetime.fromisoformat(history.get("sampled_at") or "")
        if (datetime.now(timezone.utc)-sampled).total_seconds()>120:
            upstream="unknown"
    except (ValueError,TypeError):
        upstream="unknown"
    return {"timestamp":data["timestamp"],"client_service":data["client_service"],
            "monitoring":data["monitoring"],"frps_connection":upstream,
            "total":data["total"],"active":data["active"],
            "collector_available":history["available"]}


@app.get("/api/health/tunnels")
async def health_tunnels(user=Depends(current_user)):
    data=await asyncio.to_thread(get_tunnels)
    return {"timestamp":data["timestamp"],"monitoring":data["monitoring"],
            "tunnels":[{**t,"target_health":"not_checked"} for t in data["tunnels"]]}


@app.get("/api/health/history")
async def health_history(user=Depends(current_user),limit:int=100):
    return read_health_events(limit)


@app.get("/api/health/metrics")
async def health_metrics(user=Depends(current_user)):
    return {"available":HEALTH_PUBLIC.is_file(),"latency_ms":None,
            "availability_percent":None,"transfer_bytes":None}


@app.get("/api/security/events")
async def security_events(user=Depends(current_user)):
    try:
        return await asyncio.to_thread(get_security_events)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        logging.warning("FRPS security event retrieval failed: %s", type(exc).__name__)
        raise HTTPException(503, "FRPS security event source unavailable") from None
