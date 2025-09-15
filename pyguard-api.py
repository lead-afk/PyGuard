#!/usr/bin/env python3
"""Simple pyguard API starter

Provides a /login endpoint which accepts JSON {username,password} and, on
successful authentication, returns an API key (created if missing) stored at
/etc/pyguard/api_key.

Security notes:
- This is a minimal bootstrap. Run behind TLS or bind to localhost only.
- Create the admin username and bcrypt password hash via the helper below (CLI)
  and save them to /etc/pyguard/admin_user and /etc/pyguard/admin.pass.hash
  with permissions 600.

Quick admin setup (run as root):
  python3 - <<'PY'
  import bcrypt
  from pathlib import Path
  u = 'admin'
  pw = 'choose-a-strong-password'
  Path('/etc/pyguard').mkdir(mode=0o700, exist_ok=True)
  h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
  Path('/etc/pyguard/admin_user').write_text(u)
  Path('/etc/pyguard/admin.pass.hash').write_text(h)
  import os; os.chmod('/etc/pyguard/admin_user', 0o600); os.chmod('/etc/pyguard/admin.pass.hash', 0o600)
  print('Wrote admin user and hash to /etc/pyguard')
  PY

Run:
  # development use only; for production run under uvicorn/gunicorn behind TLS
  uvicorn pyguard-api:app --host 127.0.0.1 --port 8000

Call:
  curl -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"..."}' http://127.0.0.1:8000/login
"""

from dotenv import load_dotenv

load_dotenv()

import json
from pathlib import Path
import os
from fastapi import FastAPI, HTTPException, Depends, Request, Response, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta, timezone
import base64
import hashlib

# File locations (server-side)
DATA_DIR = Path("/etc/pyguard")
ADMIN_PASS_HASH_PATH = DATA_DIR / "admin.pass.hash"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "secret_key_change_me")
ACCESS_TOKEN_EXP_SECONDS = 60 * 15
REFRESH_TOKEN_EXP_SECONDS = 60 * 60 * 24

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("pyguard-api")

# Retain HTTPBearer for optional Authorization header support but fall back to cookies.
security = None  # no longer used directly; kept for backward compatibility reference
DEBUG = os.getenv("PYGUARD_DEBUG", "1") in ("1", "true", "True")
app = FastAPI(title="PyGuard Unified API+Web", debug=DEBUG)

# ---------------- Web assets (templates + static) -----------------
_web_dir = Path(__file__).parent / "pyguard-web"
_templates_dir = _web_dir / "templates"
_static_dir = _web_dir / "static"
templates = (
    Jinja2Templates(directory=str(_templates_dir)) if _templates_dir.exists() else None
)
if _static_dir.exists():
    app.mount(
        "/static",
        StaticFiles(directory=str(_static_dir)),
        name="static",
    )

# CORS: allow web dashboard (localhost:6656) to call API with Authorization header
_default_allowed_origins = ["*"]

# Allow overriding CORS origins via env (comma separated). Set PYGUARD_CORS_ORIGINS="*" to allow all (dev only).
_env_origins = os.getenv("PYGUARD_CORS_ORIGINS")
if _env_origins:
    if _env_origins.strip() == "*":
        _allow_origins = ["*"]
    else:
        _allow_origins = [o.strip() for o in _env_origins.split(",") if o.strip()]
else:
    _allow_origins = _default_allowed_origins

# For convenience also allow common local dev hosts/ports unless user provided explicit list.
_allow_origin_regex = None
if _allow_origins == _default_allowed_origins:
    # Accept any port on 127.0.0.1 / localhost and 6656 on 0.0.0.0 and 10.0.0.x during development.
    # Note: Use PYGUARD_CORS_ORIGINS env var to override precisely in production.
    _allow_origin_regex = (
        r"http://((127\.0\.0\.1|localhost):\d+|(0\.0\.0\.0|10\.0\.0\.[0-9]{1,3}):6656)"
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_origin_regex=_allow_origin_regex,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)

log.info("CORS configured: origins=%s regex=%s", _allow_origins, _allow_origin_regex)

# ---------------- Web auth helpers & middleware -----------------

protected_routes = ["/", "/dashboard"]


def _set_auth_cookies(resp: Response, data: dict):
    resp.set_cookie(
        key="access_token",
        value=data["access_token"],
        httponly=True,
        secure=not DEBUG,
        samesite="lax",
        expires=ACCESS_TOKEN_EXP_SECONDS,
    )
    resp.set_cookie(
        key="refresh_token",
        value=data["refresh_token"],
        httponly=True,
        secure=not DEBUG,
        samesite="lax",
        expires=REFRESH_TOKEN_EXP_SECONDS,
    )
    return resp


def _clear_auth(resp: Response):
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    return resp


@app.middleware("http")
async def _web_auth_middleware(request: Request, call_next):
    path = request.url.path
    if path not in protected_routes:
        return await call_next(request)
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    should_refresh = False
    if not access_token and refresh_token:
        should_refresh = True
    if not access_token and not refresh_token:
        return RedirectResponse("/login", status_code=303)
    if access_token:
        try:
            payload = jwt.decode(access_token, JWT_SECRET_KEY, algorithms=["HS256"])
            request.state.user = payload.get("user")
            return await call_next(request)
        except jwt.ExpiredSignatureError:
            should_refresh = True
        except jwt.InvalidTokenError:
            if refresh_token:
                should_refresh = True
            else:
                resp = RedirectResponse("/login", status_code=303)
                return _clear_auth(resp)
    if should_refresh:
        # Directly invoke refresh logic instead of HTTP round-trip
        try:
            if not refresh_token:
                return RedirectResponse("/login", status_code=303)
            payload = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
            if payload.get("type") != "refresh":
                resp = RedirectResponse("/login", status_code=303)
                return _clear_auth(resp)
            # Issue new tokens
            user_data = payload.get("user")
            data = {
                "access_token": _issue_access_token(user_data),
                "refresh_token": _issue_refresh_token(user_data),
            }
            response = await call_next(request)
            response = _set_auth_cookies(response, data)
            new_payload = jwt.decode(
                data["access_token"], JWT_SECRET_KEY, algorithms=["HS256"]
            )
            request.state.user = new_payload.get("user")
            return response
        except Exception:
            resp = RedirectResponse("/login", status_code=303)
            return _clear_auth(resp)
    # fallback (should not reach here often)
    return await call_next(request)


# Lightweight request logger (focus on Origin & path)
@app.middleware("http")
async def _log_origin(request: Request, call_next):
    origin = request.headers.get("origin")
    acrm = request.headers.get("access-control-request-method")
    log.debug(
        "HTTP %s %s origin=%s preflight=%s",
        request.method,
        request.url.path,
        origin,
        bool(acrm),
    )
    try:
        resp = await call_next(request)
    except Exception as e:  # ensure we always log unexpected errors
        log.exception(
            "Unhandled error for %s %s origin=%s",
            request.method,
            request.url.path,
            origin,
        )
        raise
    return resp


@app.get("/cors-test")
def cors_test():
    return {"ok": True, "message": "CORS reachable"}


# @app.get("/")
# def root_status(request: Request):
#     return {
#         "service": "pyguard-api",
#         "cors": {
#             "allow_origins": _allow_origins,
#             "allow_origin_regex": _allow_origin_regex,
#             "request_origin": request.headers.get("origin"),
#         },
#         "status": "ok",
#     }


def generate_fernet_key(secret_key: str) -> bytes:
    digest = hashlib.sha256(secret_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)


# Initialize shared JWT secret (generated/stored under /etc/pyguard/secret.key)
try:
    from pyguard import ensure_secret_jwt as _pg_ensure_secret_jwt

    _secret = _pg_ensure_secret_jwt()
    # Refresh local constant if environment was just populated
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", _secret or JWT_SECRET_KEY)
except (
    Exception
) as _e:  # Do not block API startup if key generation fails; fallback later
    logging.warning("Failed ensure_secret_jwt at startup: %s", _e)


def get_users_file_path() -> Path:
    # path = os.getenv("PYGUARD_USERS_PATH", "invalid_users_path")
    path = os.path.join(BASE_DATA_DIR, "users.json")
    return Path(path)


def load_users_data() -> dict:
    users_path = get_users_file_path()
    print("Using users data file:", users_path)
    if not users_path.exists():
        return {}
    try:
        with open(users_path, "r") as f:
            return json.load(f)
    except Exception as e:
        log.error("Failed reading users data file: %s", e)
        return {}


def find_user_in_file(username: str) -> str | None:
    data = load_users_data()
    for user in data.get("admin_users", []):
        print("Checking user:", user.get("username"))
        if user.get("username") == username:
            return user

    return None


def save_users_data(data: dict) -> bool:
    users_path = get_users_file_path()

    try:
        with open(users_path, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        log.error("Failed writing users data file: %s", e)
        return False


def update_user_data(new_user: dict) -> bool:
    data = load_users_data()
    admin_users = data.get("admin_users", [])
    for user in admin_users:
        if user.get("name") == new_user.get("name"):
            encrypted_password = hash_password(new_user.get("password"))
            user["password_hash"] = encrypted_password
            data["admin_users"] = admin_users
            return save_users_data(data)

    raise HTTPException(status_code=404, detail="User not found")


import bcrypt


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(pw.encode(), stored_hash.encode())


def validate_registered_user(username: str, password: str) -> bool:
    """Check if the provided username is a registered admin user."""
    user = find_user_in_file(username)

    if not user:
        print("User not found:", username)
        raise HTTPException(status_code=401, detail="User not registered")
    user_hashed_password = user.get("password_hash")
    print("user_hashed_password:", user_hashed_password)
    if not verify_password(password, user_hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")


def _issue_access_token(user_data) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iat": now,
        "exp": now + timedelta(seconds=ACCESS_TOKEN_EXP_SECONDS),
        "type": "access",
        "user": user_data,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")


def _issue_refresh_token(user_data) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iat": now,
        "exp": now + timedelta(seconds=REFRESH_TOKEN_EXP_SECONDS),
        "type": "refresh",
        "user": user_data,
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")


def require_jwt(request: Request):
    """Authorize a request using either Authorization: Bearer header or access_token cookie.

    We moved to httpOnly cookies for the web UI; JS cannot read the token to set headers,
    so API endpoints must accept the cookie. Programmatic clients can still send a Bearer header.
    """
    # Prefer Authorization header if present
    auth = request.headers.get("authorization")
    token = None
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(None, 1)[1].strip()
    else:
        token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials"
        )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return {"expires_at": payload["exp"], **payload["user"]}
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


class LoginReq(BaseModel):
    username: str
    password: str


class RefreshReq(BaseModel):
    refresh_token: str


class ChangePasswordReq(BaseModel):
    old_password: str
    new_password: str


@app.get("/login", response_class=HTMLResponse)
async def web_login_page(request: Request):
    if templates is None:
        raise HTTPException(status_code=500, detail="Templates not available")
    # If already has access token cookie try decode to skip login
    token = request.cookies.get("access_token")
    if token:
        try:
            jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
            return RedirectResponse("/dashboard", status_code=303)
        except Exception:
            pass
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def unified_login(request: Request, response: Response):
    """Handle both JSON API login and form POST login.

    JSON (Content-Type: application/json) => returns token payload
    Form => sets cookies and redirects
    """
    ctype = request.headers.get("content-type", "")
    is_json = "application/json" in ctype
    try:
        if is_json:
            payload = await request.json()
            req = LoginReq(**payload)
            validate_registered_user(req.username, req.password)
            user_data = {"username": req.username}
            token = _issue_access_token(user_data)
            refresh = _issue_refresh_token(user_data)
            return {
                "access_token": token,
                "token_type": "bearer",
                "expires_in": ACCESS_TOKEN_EXP_SECONDS,
                "refresh_token": refresh,
            }
        # Form login
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        if not username or not password:
            if templates is None:
                raise HTTPException(status_code=400, detail="Invalid credentials")
            return templates.TemplateResponse(
                "login.html", {"request": request, "error": "Invalid credentials"}
            )
        validate_registered_user(username, password)
        user_data = {"username": username}
        token = _issue_access_token(user_data)
        refresh = _issue_refresh_token(user_data)
        redirect = RedirectResponse("/dashboard", status_code=303)
        _set_auth_cookies(redirect, {"access_token": token, "refresh_token": refresh})
        return redirect
    except HTTPException:
        if is_json:
            raise
        if templates is None:
            raise
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password"}
        )


@app.post("/logout")
async def web_logout(response: Response):
    _clear_auth(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.get("/")
async def root_redirect():
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if templates is None:
        raise HTTPException(status_code=500, detail="Templates not available")
    # Attempt to get current user from state (middleware)
    interfaces = []
    try:
        interfaces = list_interfaces()
    except Exception:
        interfaces = []
    log.info("Render dashboard with %d interfaces", len(interfaces))
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "interfaces": interfaces}
    )


@app.post("/refresh")
def refresh(req: RefreshReq):
    """Exchange a valid refresh token for a new short-lived access JWT."""
    try:
        payload = jwt.decode(req.refresh_token, JWT_SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=403, detail="Wrong token type")
    except:
        raise HTTPException(status_code=403, detail="Invalid refresh token")

    token = _issue_access_token(payload.get("user"))
    refresh = _issue_refresh_token(payload.get("user"))

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXP_SECONDS,
        "refresh_token": refresh,
    }


@app.get("/user")
def get_user_info(user=Depends(require_jwt)):
    return user


@app.post("/change-password")
def api_change_password(
    req: ChangePasswordReq, response: Response, user=Depends(require_jwt)
):
    """Change the admin password (requires valid access token)."""

    try:
        validate_registered_user(user.get("username"), req.old_password)
    except HTTPException:
        raise HTTPException(status_code=401, detail="Incorrect password")

    update_user_data({"username": user.get("username"), "password": req.new_password})

    response.status_code = status.HTTP_200_OK


# ---------------------------------------------------------------------------
# PyGuard management endpoints (all require valid JWT)
# ---------------------------------------------------------------------------

# Import pyguard core functions (they enforce root internally where needed)
try:
    from pyguard import *
except Exception as e:  # pragma: no cover (import failure surfaces via API error)
    raise RuntimeError(f"Failed importing pyguard core: {e}")


class InitInterfaceReq(BaseModel):
    interface: str
    port: int | None = None
    network: str | None = None
    public_ip: str | None = None


class UpdateServerReq(BaseModel):
    name: str | None = None
    port: int | None = None
    dns: str | None = None
    public_ip: str | None = None
    network: str | None = None
    forward_to_docker_bridge: bool | None = None
    dns_service: bool | None = None
    allow_vpn_gateway: bool | None = None

    old_port: int | None = None
    old_dns: str | None = None
    old_public_ip: str | None = None
    old_network: str | None = None
    old_forward_to_docker_bridge: bool | None = None
    old_dns_service: bool | None = None
    old_allow_vpn_gateway: bool | None = None


class AddPeerReq(BaseModel):
    name: str
    peer_ip: str
    allowed_ips: str


class ValidatePeerReq(BaseModel):
    name: str
    ip: str | None = None
    # Optional fields for edit validation
    old_name: str | None = None
    old_ip: str | None = None
    new_allowed: str | None = None
    old_allowed: str | None = None


class ValidateInterface(BaseModel):
    interface: str
    port: int
    network: str

    ignore_range_check: bool = True

    old_interface: str | None = None
    old_port: int | None = None
    old_network: str | None = None


class BulkAddPeersReq(BaseModel):
    peers: list[AddPeerReq]


class UpdatePeerReq(BaseModel):
    allowed_ips: str | None = None
    ip: str | None = None
    new_name: str | None = None
    rotate_keys: bool = False


class CustomCommandReq(BaseModel):
    command: str


def _filter_server(server: dict, include_private: bool = False) -> dict:
    s = dict(server)
    if not include_private and "private_key" in s:
        s.pop("private_key")
    return s


@app.get("/interfaces")
def api_list_interfaces(_=Depends(require_jwt)):
    data = list_interfaces()
    return {
        "interfaces": data,
        "PYGUARD_IN_DOCKER": os.getenv("PYGUARD_IN_DOCKER") == "1",
    }


@app.get("/interfaces/defaults")
def api_list_interfaces(_=Depends(require_jwt)):

    name, port, network, public_ip = get_new_interface_defaults()

    data = {"name": name, "port": port, "network": network, "public_ip": public_ip}
    return data


@app.post("/interfaces/add", status_code=201)
def api_init_interface(req: InitInterfaceReq, _=Depends(require_jwt)):
    # Basic validation
    if not req.interface or any(c.isspace() for c in req.interface):
        raise HTTPException(status_code=400, detail="Invalid interface name")
    # Reuse core init (prints to stdout; ignore). We don't want CLI printouts; so just call.
    init_server(
        req.interface, port=req.port, network=req.network, public_ip=req.public_ip
    )
    d = load_data(req.interface)
    if not d.get("server").get("private_key"):
        raise HTTPException(status_code=500, detail="Failed to initialize server")
    data = list_interfaces()
    try:
        peers_obj = get_peers_info(req.interface, specific_peer=None)
    except Exception as e:
        logging.exception("Failed gathering peer info for %s: %s", req.interface, e)
        peers_obj = None
    resp = {
        "interface": req.interface,
        "server": _filter_server(d.get("server", {})),
        "peers": peers_obj,
        "peer_count": len(peers_obj) if peers_obj else len(d.get("peers", {})),
        "active": is_interface_active(req.interface),
    }
    print("Successful initialization of interface:", req.interface)
    return {"interface": req.interface, "interfaces": data, "new_data": resp}


@app.get("/interfaces/{interface}")
def api_get_interface(interface: str, _=Depends(require_jwt)):
    """Return interface summary + live peer status.

    Returns a native dict in the `peers` field (never a JSON string).
    """
    path = data_path(interface)
    if isinstance(path, str):  # normalize
        path = Path(path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Interface not found")
    d = load_data(interface)
    # Get dict form (no JSON dump) so FastAPI serializes naturally
    try:
        peers_obj = get_peers_info(interface, specific_peer=None)
        if not isinstance(peers_obj, dict):  # very defensive
            peers_obj = {}
    except Exception as e:
        # Don't fail whole endpoint for peer runtime parsing issues
        logging.exception("Failed gathering peer info for %s: %s", interface, e)
        peers_obj = {}
    resp = {
        "interface": interface,
        "server": _filter_server(d.get("server", {})),
        "peers": peers_obj,
        "peer_count": len(peers_obj) if peers_obj else len(d.get("peers", {})),
        "active": is_interface_active(interface),
        "forward_to_docker_bridge": d.get("forward_to_docker_bridge", False),
        "PYGUARD_IN_DOCKER": os.getenv("PYGUARD_IN_DOCKER") == "1",
        "dns_service": d.get("dns_service", False),
        "allow_vpn_gateway": d.get("allow_vpn_gateway", False),
    }
    return resp


@app.post("/interfaces/{interface}/delete")
def api_delete_interface(interface: str, _=Depends(require_jwt)):
    # Lazy import delete (avoids circular)

    path = data_path(interface)
    if isinstance(path, str):
        path = Path(path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Interface not found")
    print("Deleting interface:", interface)
    delete_interface(interface)
    data = list_interfaces()
    return {"deleted": True, "interface": interface, "interfaces": data}


@app.post("/interfaces/validate")
def api_validate_interface(req: ValidateInterface, _=Depends(require_jwt)):
    # Validate the interface configuration

    ignore_name: bool = False
    ignore_port: bool = False
    ignore_network: bool = False
    if req.old_interface and req.old_interface == req.interface:
        ignore_name = True
    if req.old_port and req.old_port == req.port:
        ignore_port = True
    if req.old_network and req.old_network == req.network:
        ignore_network = True

    ok, meta = validate_new_interface(
        req.interface,
        req.port,
        req.network,
        ignore_range_check=req.ignore_range_check,
        ignore_name=ignore_name,
        ignore_port=ignore_port,
        ignore_network=ignore_network,
    )
    if not ok:
        raise HTTPException(status_code=400, detail=meta.get("error", "Unknown error"))

    return {"ok": True}


@app.post("/interfaces/{interface}/server/update")
def api_update_server(interface: str, req: UpdateServerReq, _=Depends(require_jwt)):
    # Apply each provided field using CLI core update_config semantics

    something_changed = False

    if req.port is not None and req.port != req.old_port:
        update_config(interface, "port", "port", str(req.port))
        something_changed = True
    if req.dns is not None and req.dns != req.old_dns:
        update_config(interface, "dns", "dns", req.dns)
        something_changed = True
    if req.public_ip is not None and req.public_ip != req.old_public_ip:
        update_config(interface, "public-ip", "public-ip", req.public_ip)
        something_changed = True
    if req.network is not None and req.network != req.old_network:
        update_config(interface, "network", "network", req.network)
        something_changed = True
    if (
        req.forward_to_docker_bridge is not None
        and req.forward_to_docker_bridge != req.old_forward_to_docker_bridge
    ):
        update_config(
            interface,
            "forward_to_docker_bridge",
            "forward_to_docker_bridge",
            str(req.forward_to_docker_bridge),
        )
        something_changed = True
    if req.dns_service is not None and req.dns_service != req.old_dns_service:
        update_config(interface, "dns_service", "dns_service", str(req.dns_service))
        something_changed = True
    if (
        req.allow_vpn_gateway is not None
        and req.allow_vpn_gateway != req.old_allow_vpn_gateway
    ):
        update_config(
            interface,
            "allow_vpn_gateway",
            "allow_vpn_gateway",
            str(req.allow_vpn_gateway),
        )
        something_changed = True

    if req.name is not None and interface != req.name:
        rename_interface(interface, req.name)
        interface = req.name
        something_changed = True

    d = load_data(interface)
    if not d.get("server").get("private_key"):
        raise HTTPException(status_code=500, detail="Failed to initialize server")
    data = list_interfaces()
    try:
        peers_obj = get_peers_info(interface, specific_peer=None)
    except Exception as e:
        logging.exception("Failed gathering peer info for %s: %s", interface, e)
        peers_obj = None
    resp = {
        "interface": interface,
        "server": _filter_server(d.get("server", {})),
        "peers": peers_obj,
        "peer_count": len(peers_obj) if peers_obj else len(d.get("peers", {})),
        "active": is_interface_active(interface),
        "forward_to_docker_bridge": d.get("forward_to_docker_bridge", False),
        "dns_service": d.get("dns_service", False),
        "allow_vpn_gateway": d.get("allow_vpn_gateway", False),
    }
    print("Successful initialization of interface:", interface)
    return {
        "interface": interface,
        "interfaces": data,
        "new_data": resp,
        "something_changed": something_changed,
    }


@app.get("/interfaces/{interface}/next_available")
def api_get_next_available_ip(interface: str, _=Depends(require_jwt)):
    next = get_next_ip(interface)
    if not next:
        raise HTTPException(status_code=404, detail="No available IP found")
    return {"interface": interface, "next_available_ip": next}


@app.get("/interfaces/{interface}/peers")
def api_list_peers(interface: str, hide_private: bool = True, _=Depends(require_jwt)):
    peers = list_peers(interface)
    if peers is None:
        raise HTTPException(status_code=404, detail="Interface not found")
    if hide_private:
        for p in peers:
            p.pop("private_key", None)
    return {"interface": interface, "peers": peers}


@app.post("/interfaces/{interface}/peers/validate")
def api_validate_peer(interface: str, body: ValidatePeerReq, _=Depends(require_jwt)):
    """Validate a prospective peer name/IP without creating it.

    Returns:
      {"ok": True} on success or HTTP 400 with {"detail": <reason>}.
      Accepts optional IP; if omitted the next-available IP logic would apply when creating.
    """
    if not body.name:
        raise HTTPException(status_code=400, detail="name required")
    # If IP not supplied we still validate name uniqueness & reserved word.
    test_ip = body.ip if body.ip is not None else get_next_ip(interface)
    old_name = body.old_name if body.old_name is not None else None
    old_ip = body.old_ip if body.old_ip is not None else None

    ignore_name: bool = False
    ignore_ip: bool = False
    if old_name and old_name == body.name:
        ignore_name = True
    if old_ip and old_ip == test_ip:
        ignore_ip = True

    try:
        ok, meta = check_new_peer(
            interface, body.name, test_ip, ignore_name=ignore_name, ignore_ip=ignore_ip
        )
    except HTTPException:
        raise
    except Exception as e:
        print("Error during peer 11111111111111111111 validation:", e)
        raise HTTPException(status_code=500, detail=f"validation failed: {e}")
    if not ok:
        # meta contains {'error': ...}
        raise HTTPException(status_code=400, detail=meta.get("error", "invalid"))
    to_return = {"ok": True, "interface": interface, "name": body.name, "ip": test_ip}

    if (
        body.new_allowed is not None
        and body.old_allowed is not None
        and body.new_allowed != body.old_allowed
    ) or (body.new_allowed is not None):
        try:
            ok, meta = validate_allowed_ips(interface, body.new_allowed)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid allowed_ips: {e}")

        if not ok:
            raise HTTPException(status_code=400, detail=meta.get("error", "invalid"))

    return to_return


def _create_peer(interface: str, req: AddPeerReq):
    if not req.name:
        raise HTTPException(status_code=400, detail="Peer name required")
    add_peer(interface, req.name, peer_ip=req.peer_ip, allowed_ips=req.allowed_ips)
    peer_obj = show_peer_config(interface, req.name)
    if not peer_obj:
        raise HTTPException(status_code=500, detail="Failed to add peer")
    peers_obj = get_peers_info(interface)
    return peers_obj


@app.post("/shell/port/{port}", status_code=201)
def api_allow_port(port: str, _=Depends(require_jwt)):

    settings = load_settings()
    if not settings.get("allow_command_apply"):
        raise HTTPException(
            status_code=403,
            detail="Command application is not allowed, enable it in settings",
        )

    ensure_root()

    if not command_exists("ufw"):
        raise HTTPException(status_code=400, detail="ufw command not found")

    subprocess.run(["ufw", "allow", port], check=True)

    return {"port": port}


@app.post("/shell/route/{interface}", status_code=201)
def api_allow_route(interface: str, _=Depends(require_jwt)):

    settings = load_settings()
    if not settings.get("allow_command_apply"):
        raise HTTPException(
            status_code=403,
            detail="Command application is not allowed, enable it in settings",
        )

    ensure_root()

    if not command_exists("ufw"):
        raise HTTPException(status_code=400, detail="ufw command not found")

    subprocess.run(
        ["ufw", "route", "allow", "in", "on", interface, "out", "on", interface],
        check=True,
    )

    return {"interface": interface}


@app.post("/interfaces/{interface}/peers", status_code=201)
def api_add_peer_legacy(interface: str, req: AddPeerReq, _=Depends(require_jwt)):
    """(Deprecated) Create a peer. Prefer POST /interfaces/{interface}/peers/add"""
    obj = _create_peer(interface, req)
    obj["deprecated_endpoint"] = True
    return obj


@app.post("/interfaces/{interface}/peers/add", status_code=201)
def api_add_peer(interface: str, req: AddPeerReq, _=Depends(require_jwt)):
    return _create_peer(interface, req)


@app.get("/interfaces/{interface}/peers/{peer}")
def api_get_peer(
    interface: str, peer: str, include_private: bool = True, _=Depends(require_jwt)
):
    obj = show_peer_config(interface, peer)
    if obj is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    if not include_private:
        obj["peer_data"].pop("private_key", None)
    return obj


@app.post("/interfaces/{interface}/peers/{peer}/delete")
def api_delete_peer(interface: str, peer: str, _=Depends(require_jwt)):
    # Verify exists first
    obj = show_peer_config(interface, peer)
    if obj is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    ok, meta = remove_peer(interface, peer)
    if not ok:
        raise HTTPException(status_code=400, detail=meta.get("error", "invalid"))
    return {"deleted": True, "peer": peer, "interface": interface}


@app.post("/interfaces/{interface}/peers/{peer}/update")
def api_update_peer(
    interface: str, peer: str, req: UpdatePeerReq, _=Depends(require_jwt)
):
    # Ensure peer exists first
    existing = show_peer_config(interface, peer)
    if existing is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    did_any = False
    current_name = peer
    current_peer = existing.get("peer_data", {})
    if req.allowed_ips is not None and req.allowed_ips != current_peer.get(
        "allowed_ips"
    ):
        update_config(interface, current_name, "allowed-ips", req.allowed_ips)
        did_any = True
    # ip change
    if req.ip is not None and req.ip != current_peer.get("ip"):
        update_config(interface, current_name, "ip", req.ip)
        did_any = True
    # rotate keys
    if req.rotate_keys:
        update_config(interface, current_name, "rotate-keys", "")
        did_any = True
    # rename (do last so earlier updates refer to original name)
    if req.new_name is not None and req.new_name != current_name:
        update_config(interface, current_name, "rename", req.new_name)
        current_name = req.new_name
        did_any = True
    if not did_any:
        raise HTTPException(
            status_code=400,
            detail="Nothing changed!",
        )
    # Fetch updated peer state using the final name after potential rename
    obj = show_peer_config(interface, current_name)
    if obj is None:
        raise HTTPException(
            status_code=500, detail="Peer state unavailable after update"
        )
    obj["peer_data"].pop("private_key", None)
    # Provide interface summary and final peer name
    data = api_get_interface(interface)
    return {"name": current_name, "interface": data, "peer": obj}


@app.post("/interfaces/{interface}/peers/{peer}/rotate")
def api_rotate_peer(interface: str, peer: str, _=Depends(require_jwt)):
    rotate_peer_key(interface, peer)
    obj = show_peer_config(interface, peer)
    if obj is None:
        raise HTTPException(status_code=404, detail="Peer not found after rotate")
    obj["peer_data"].pop("private_key", None)
    return {"rotated": True, "peer": peer, "interface": interface, "peer_state": obj}


class RenamePeerReq(BaseModel):
    new_name: str


@app.post("/interfaces/{interface}/peers/{peer}/rename")
def api_rename_peer(
    interface: str, peer: str, req: RenamePeerReq, _=Depends(require_jwt)
):
    if not req.new_name:
        raise HTTPException(status_code=400, detail="new_name required")
    rename_peer(interface, peer, req.new_name)
    obj = show_peer_config(interface, req.new_name)
    if obj is None or obj.get("peer_data", {}).get("name") != req.new_name:
        raise HTTPException(status_code=500, detail="Rename failed")
    obj["peer_data"].pop("private_key", None)
    return {"renamed": True, "old": peer, "new": req.new_name, "interface": interface}


@app.post("/interfaces/{interface}/peers/bulk", status_code=201)
def api_bulk_add_peers_legacy(
    interface: str, req: BulkAddPeersReq, _=Depends(require_jwt)
):
    """(Deprecated) bulk add peers. Prefer /peers/bulk-add"""
    created = []
    errors = []
    for entry in req.peers:
        try:
            add_peer(interface, entry.name, allowed_ips=entry.allowed_ips)
            obj = show_peer_config(interface, entry.name)
            if obj:
                obj["peer_data"].pop("private_key", None)
                created.append(obj)
            else:
                errors.append({"name": entry.name, "error": "creation_failed"})
        except Exception as e:  # noqa
            errors.append({"name": entry.name, "error": str(e)})
    return {"created": created, "errors": errors, "deprecated_endpoint": True}


@app.post("/interfaces/{interface}/peers/bulk-add", status_code=201)
def api_bulk_add_peers(interface: str, req: BulkAddPeersReq, _=Depends(require_jwt)):
    created = []
    errors = []
    for entry in req.peers:
        try:
            add_peer(interface, entry.name, allowed_ips=entry.allowed_ips)
            obj = show_peer_config(interface, entry.name)
            if obj:
                obj["peer_data"].pop("private_key", None)
                created.append(obj)
            else:
                errors.append({"name": entry.name, "error": "creation_failed"})
        except Exception as e:  # noqa
            errors.append({"name": entry.name, "error": str(e)})
    return {"created": created, "errors": errors}


@app.get("/interfaces/{interface}/custom/{direction}")
def api_list_custom(interface: str, direction: str, _=Depends(require_jwt)):
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction must be up or down")
    d = load_data(interface)
    cmds = d.get("server", {}).get(
        "custom_post_up" if direction == "up" else "custom_post_down", []
    )
    return {"interface": interface, "direction": direction, "commands": cmds}


@app.post("/interfaces/{interface}/custom/{direction}", status_code=201)
def api_add_custom(
    interface: str, direction: str, req: CustomCommandReq, _=Depends(require_jwt)
):
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction must be up or down")
    if not req.command:
        raise HTTPException(status_code=400, detail="command required")
    add_custom_command(interface, direction, req.command)
    return {"added": True}


@app.post("/interfaces/{interface}/custom/{direction}/{index}/delete")
def api_delete_custom(
    interface: str, direction: str, index: int, _=Depends(require_jwt)
):
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction must be up or down")
    # delete_custom_command can remove by index (1-based) or command string; we pass index as string
    delete_custom_command(interface, direction, str(index))
    return {"deleted": True}


@app.post("/interfaces/{interface}/start")
def api_start_interface(interface: str, _=Depends(require_jwt)):
    start_wireguard(interface)
    return {"started": True, "interface": interface}


@app.post("/interfaces/{interface}/stop")
def api_stop_interface(interface: str, _=Depends(require_jwt)):
    stop_wireguard(interface)
    return {"stopped": True, "interface": interface}


@app.get("/interfaces/{interface}/runtime")
def api_runtime_status(interface: str, _=Depends(require_jwt)):
    # Provide raw output of 'wg show <iface>' (safe; may include public keys)
    import subprocess, shlex

    try:
        res = subprocess.run(
            ["wg", "show", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return {"interface": interface, "raw": res.stdout}
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=400, detail=e.stderr.strip() or "wg show failed"
        )


# ---------------- Additional modification/control endpoints -----------------


@app.post("/interfaces/{interface}/regenerate")
def api_regenerate_config(interface: str, _=Depends(require_jwt)):
    # Force rebuild of server config (will also restart if active)
    try:
        generate_config(interface)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"regenerated": True, "interface": interface}


@app.post("/interfaces/{interface}/service/enable")
def api_enable_service(interface: str, _=Depends(require_jwt)):
    try:
        enable_service(interface)
        start_wireguard(interface)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    data = list_interfaces()
    return {
        "service_enabled": True,
        "interface": interface,
        "data": data,
        "active": is_interface_active(interface),
    }


@app.post("/interfaces/{interface}/service/disable")
def api_disable_service(interface: str, _=Depends(require_jwt)):
    try:
        stop_wireguard(interface)
        disable_service(interface)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    data = list_interfaces()
    return {
        "service_disabled": True,
        "interface": interface,
        "data": data,
        "active": is_interface_active(interface),
    }


class PeerConfigReq(BaseModel):
    save: bool = False


@app.post("/interfaces/{interface}/peers/{peer}/config")
def api_peer_config(
    interface: str, peer: str, body: PeerConfigReq, _=Depends(require_jwt)
):
    cfg_obj = show_peer_config(interface, peer)
    if cfg_obj is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    # Produce client config text (this path includes private key inside peer_data)
    text_cfg = generate_peer_config(interface, peer)
    if text_cfg is None:
        raise HTTPException(status_code=500, detail="Failed generating config")
    if body.save:
        # will write file under ./client_configs relative to API working dir
        try:
            from pyguard import save_client_config

            save_client_config(peer, text_cfg)
        except Exception:
            pass
    # Hide server private key & peer private key in response but include peer private if explicitly asked? Always hide for safety.
    cfg_obj["peer_data"].pop("private_key", None)
    return {"meta": cfg_obj, "client_config": text_cfg}


@app.get("/interfaces/{interface}/peers/{peer}/qr")
def api_peer_qr(interface: str, peer: str, _=Depends(require_jwt)):
    """Return base64 PNG QR for the peer's client config."""
    import subprocess, base64, tempfile

    text_cfg = generate_peer_config(interface, peer)
    if text_cfg is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    # Use qrencode to stdout (-o -)
    try:
        proc = subprocess.run(
            ["qrencode", "-t", "PNG", "-o", "-"],
            input=text_cfg.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="qrencode not installed on server")
    except subprocess.CalledProcessError as e:
        raise HTTPException(
            status_code=500, detail=f"qrencode failed: {e.stderr.decode().strip()}"
        )
    b64 = base64.b64encode(proc.stdout).decode()
    return {"peer": peer, "interface": interface, "qr_png_base64": b64}
