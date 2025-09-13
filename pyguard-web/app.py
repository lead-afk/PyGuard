import os
import httpx
import logging
import jwt
from fastapi import Cookie, Depends, FastAPI, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from dotenv import load_dotenv

load_dotenv()

API_BASE = os.environ.get("PYGUARD_API_BASE", "http://127.0.0.1:6655")


def _load_jwt_secret() -> str:
    # Attempt to call ensure_secret_jwt if pyguard core importable (same virtualenv/container)
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret:
        try:
            from pyguard import ensure_secret_jwt as _pg_ensure_secret_jwt

            secret = _pg_ensure_secret_jwt()
        except Exception as _e:  # fallback to reading file (e.g., running unprivileged)
            key_path = "/etc/pyguard/secret.key"
            try:
                with open(key_path, "r", encoding="utf-8") as f:
                    secret = f.read().strip()
            except Exception:
                logging.warning("JWT secret not available yet (%s)", _e)
    return secret or "secret_key_change_me"


JWT_SECRET_KEY = _load_jwt_secret()
DEBUG = os.environ.get("PYGUARD_WEB_DEBUG", "1") in ("1", "true", "True")
ACCESS_TOKEN_EXP_SECONDS = 60 * 15
REFRESH_TOKEN_EXP_SECONDS = 60 * 60 * 24

logging.basicConfig(level=logging.INFO)
templates = Jinja2Templates(
    directory=str(os.path.join(os.path.dirname(__file__), "templates"))
)
log = logging.getLogger("pyguard-web")
app = FastAPI(title="PyGuard Web", debug=DEBUG)
app.mount(
    "/static",
    StaticFiles(directory=str(os.path.join(os.path.dirname(__file__), "static"))),
    name="static",
)

# Always reload Jinja templates in development
try:
    templates.env.auto_reload = True
    # Disable template bytecode cache in dev to force recompile
    templates.env.cache = {}
except Exception:
    pass


def get_current_user(request: Request):
    return getattr(request.state, "user", None)


def get_auth_token(request: Request):
    return request.cookies.get("access_token")


def clear_auth_cookies(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response


def create_api_headers(request: Request) -> dict[str, str]:
    auth_token = get_auth_token(request)

    return {"Authorization": f"Bearer {auth_token}"} if auth_token else {}


def check_if_token_exists(request: Request):
    return get_auth_token(request) is not None


def set_auth_cookies(response: Response, data: dict):
    response.set_cookie(
        key="access_token",
        value=data["access_token"],
        httponly=True,
        secure=not DEBUG,
        samesite="lax",
        expires=ACCESS_TOKEN_EXP_SECONDS,
    )
    response.set_cookie(
        key="refresh_token",
        value=data["refresh_token"],
        httponly=True,
        secure=not DEBUG,
        samesite="lax",
        expires=REFRESH_TOKEN_EXP_SECONDS,
    )

    return response


protected_routes = ["/", "/dashboard"]


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    should_refresh_token = False

    if not path in protected_routes:
        return await call_next(request)

    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    if not access_token and refresh_token:
        should_refresh_token = True

    if not access_token and not refresh_token:
        return RedirectResponse("/login", status_code=303)

    if access_token:
        try:
            payload = jwt.decode(access_token, JWT_SECRET_KEY, algorithms=["HS256"])
            request.state.user = payload.get("user")

            return await call_next(request)
        except jwt.ExpiredSignatureError:
            refresh_token = True
        except jwt.InvalidTokenError:
            if refresh_token:
                should_refresh_token = True
            else:
                response = RedirectResponse("/login", status_code=303)
                response = clear_auth_cookies(response)
                return response

    if should_refresh_token:
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                if not refresh_token:
                    return RedirectResponse("/login", status_code=303)

                resp = await client.post(
                    f"{API_BASE}/refresh", json={"refresh_token": refresh_token}
                )

                if resp.status_code != 200:
                    response = RedirectResponse("/login", status_code=303)
                    response = clear_auth_cookies(response)
                    return response

                data = resp.json()

                response = await call_next(request)
                response = set_auth_cookies(response, data)
                new_token_data = jwt.decode(
                    data["access_token"], JWT_SECRET_KEY, algorithms=["HS256"]
                )
                request.state.user = new_token_data.get("user")

                return response
            except httpx.RequestError:
                response = RedirectResponse("/login", status_code=303)
                response = clear_auth_cookies(response)
                return response


@app.get("/")
async def root(request: Request):
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/login")
async def login_page(request: Request):
    if check_if_token_exists(request):
        return RedirectResponse("/dashboard", status_code=303)

    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
async def handle_login(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
):
    error_message = None

    if not username or not password:
        error_message = "Invalid username or password"

    if not error_message:
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.post(
                    f"{API_BASE}/login",
                    json={"username": username, "password": password},
                )

                print(resp.status_code, resp.json())

                if resp.status_code != 200:
                    log.info("Login failed: status=%s", resp.status_code)
                    error_message = "Invalid username or password"
                else:
                    data = resp.json()
                    if "access_token" not in data:
                        log.error("API /login response missing access_token: %s", data)
                        error_message = "Malformed API response"
                    else:
                        log.info("Login success, redirecting to /dashboard")

                        redirect_response = RedirectResponse(
                            "/dashboard", status_code=303
                        )
                        redirect_response.set_cookie(
                            key="access_token",
                            value=data["access_token"],
                            httponly=True,
                            secure=not DEBUG,
                            samesite="lax",
                            expires=60 * 15,  # 15 minutes
                        )
                        redirect_response.set_cookie(
                            key="refresh_token",
                            value=data["refresh_token"],
                            httponly=True,
                            secure=not DEBUG,
                            samesite="lax",
                            expires=60 * 60 * 24,  # 24 hours
                        )

                        return redirect_response
            except httpx.RequestError:
                raise HTTPException(status_code=502, detail="API unreachable")

    return templates.TemplateResponse(
        "login.html", {"request": request, "error": error_message}
    )


@app.post("/logout")
async def handle_logout(response: Response):
    clear_auth_cookies(response)

    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    headers = create_api_headers(request)
    interfaces = []

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(f"{API_BASE}/interfaces", headers=headers)
            if r.status_code == 200:
                interfaces = r.json().get("interfaces", [])
        except httpx.RequestError:
            pass

    log.info("Render dashboard with %d interfaces", len(interfaces))

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "interfaces": interfaces,
        },
    )


# Legacy proxy endpoints removed in unified mode.
