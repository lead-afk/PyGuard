# PyGuard

Self‑hosted WireGuard management toolkit that bundles:

- A batteries‑included Python CLI (`pyguard.py`) for provisioning & managing WireGuard interfaces, peers, DNS, and systemd services
- A FastAPI powered HTTP+Web UI (`pyguard-api.py`) with login, JWT (httpOnly cookies), dashboard & REST endpoints
- An optional lightweight authoritative / forwarding DNS service (`pyguard-dns.py`) that can answer interface‑local hostnames and forward the rest (`WIP`)
- A Docker image (userspace `wireguard-go`) for portable deployments where kernel modules are unavailable

Status: early (alpha) – APIs & data layout may still change. Feedback / issues welcome.

---

## Highlights

- Pure Python management (no external DB) – state stored as JSON per interface in `/etc/pyguard/<iface>.conf`
- Automatic interface bootstrap (keys, config render, systemd service) and launch orchestration
- Peer lifecycle: add, list, revoke, regenerate configs + optional QR render (uses `qrencode`)
- Intelligent defaults: next available port, network and IP auto‑selection avoiding collisions
- Built‑in JWT auth with refresh rotation (cookies) for the web dashboard
- CORS configurable via `PYGUARD_CORS_ORIGINS`
- Userspace WireGuard (`wireguard-go`) container image, run without kernel module (e.g. certain VPS / containers)
- Optional embedded DNS responder (A / AAAA) with upstream forwarder
- Systemd integration for per‑interface services (e.g. `pyguard-wg0.service`)

---

## Repository Layout

```
pyguard.py              # Core CLI / engine
pyguard-api.py          # FastAPI app (REST + Web UI)
pyguard-dns.py          # Lightweight DNS server
pyguard-web/            # Templates & static assets
docker/                 # Dockerfile + compose example
scripts/                # Helper scripts (password hash, reset-admin etc.)
data/ (example)         # Example users / logs (production uses /etc/pyguard)
```

Runtime critical directories (created automatically if missing):

- `/etc/pyguard` – state, secrets, users, interface JSON (`<iface>.conf`), `secret.key`
- `/etc/wireguard` – rendered WireGuard configs consumed by `wg-quick`
- `/var/log/pyguard` – log outputs (in container / when supervised)

---

## Features (Detail)

| Area           | Capabilities                                                                      |
| -------------- | --------------------------------------------------------------------------------- |
| Interfaces     | init, list, delete, generate keys, launch/stop, autostart toggle                  |
| Peers          | add, remove, show, export config, QR code, stats (handshake, transfer)            |
| Networking     | Auto port & network selection, AllowedIPs defaults, gateway forwarding (optional) |
| DNS (optional) | Local records & forwarding, updates on peer changes                               |
| Auth           | Bcrypt admin users, JWT access/refresh rotation via cookies                       |
| Deployment     | Bare metal (systemd), Docker userspace `wireguard-go` image                       |

---

## Quick Start (Native Linux)

Requirements:

- Python 3.11+
- Root privileges (WireGuard + writing to `/etc`)
- WireGuard tools (`wg`, `wg-quick`) – auto install attempted on Debian/Ubuntu

```bash
git clone https://github.com/lead-afk/PyGuard.git
cd PyGuard
./init-project.sh

# (As root) initialize first interface
sudo ./pyguard.py init wg0
sudo ./pyguard.py apply wg0   # write config + bring up

# Launch API (see 'API Root Requirements' below)
uvicorn pyguard-api:app --host 127.0.0.1 --port 6656
```

Visit: http://127.0.0.1:6656 (after creating an admin user – see below).

---

## Admin User Setup

PyGuard stores admin users in `/etc/pyguard/users.json` (bcrypt hashed passwords).

Create first admin account:

```bash
python scripts/reset-admin.py  # helper if present (or use snippet below)
```

Manual creation (Python one‑liner):

```bash
python - <<'PY'
import bcrypt, json, os, pathlib
base = pathlib.Path('/etc/pyguard'); base.mkdir(mode=0o700, exist_ok=True)
u = 'admin'
pw = 'choose-a-strong-password'
data = {'admin_users':[{'username':u,'password_hash':bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()}]}
with open(base/'users.json','w') as f: json.dump(data,f,indent=2)
os.chmod(base/'users.json',0o600)
print('Created admin user ->', u)
PY
```

Login at `/login` with those credentials. JWT secrets are auto‑generated in `/etc/pyguard/secret.key`.

---

### API Root Requirements & Safer Launch Options

Why this is tricky: many backend actions (creating interfaces, starting/stopping them, touching `/etc/wireguard`, generating keys, writing `/etc/pyguard/*.conf`) inherently need root (CAP_NET_ADMIN, file ownership). Running `sudo uvicorn ...` is usually discouraged for security & hygiene (and can drop env, virtualenv context, etc.) and unavalible anyway. Below are options:

1. Container (Recommended)

- Use the provided Docker image / compose file. The container runs with the capabilities it needs (NET_ADMIN + /dev/net/tun) while isolating the process.

2. Systemd Service (Host Root, Controlled Scope)

- Create a unit, limit capabilities and lock down filesystem:

  ```ini
  [Unit]
  Description=PyGuard API
  After=network.target

  [Service]
  WorkingDirectory=<path_to_repo>/pyguard
  ExecStart= <path_to_repo>/pyguard/.venv/bin/python -m uvicorn pyguard-api:app --host 0.0.0.0 --port 6656
  Environment="PATH=<path_to_repo>/pyguard/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
  User=root
  Group=root
  ProtectSystem=full
  ProtectHome=true
  Restart=on-failure
  RestartSec=5s

  [Install]
  WantedBy=multi-user.target
  ```

- Then: `systemctl daemon-reload && systemctl enable --now pyguard-api`.

Security Notes:

- Avoid exposing a root-run uvicorn directly to the internet; put a reverse proxy (Caddy / Nginx / Traefik) in front and restrict firewall access.
- Minimize capabilities: only `CAP_NET_ADMIN` and maybe `CAP_NET_BIND_SERVICE` (<1024 ports) are typically needed. The current default port 6656 does not require bind capabilities.
- Keep `/etc/pyguard/secret.key` mode 600 owned by root (or root:pyguard with 640 and group membership for the service account).

---

## CLI Overview

The README previously listed legacy prototype commands (apply / addPeer / showPeer etc.). Below is the accurate, current command surface taken from `pyguard.py`.

Top‑level commands:

- `pyguard help | -h | --help` – show extended help (includes examples)
- `pyguard list [--json]` – list all interfaces (name, port, network, peers, active)
- `pyguard init [<iface>] [--port N] [--network CIDR] [--public-ip HOST]` – create new interface (auto picks defaults if omitted)
- `pyguard delete <iface> [<iface2> ...]` – delete one or more interfaces (state + config + systemd unit)
- `pyguard launchAll` – start every interface with `launch_on_start=true`
- `pyguard stopAll` – stop all active interfaces

Interface‑scoped commands (first positional arg is the interface):

- `pyguard <iface> start | stop | status` – bring interface up/down (wg-quick) or show live peer stats
- `pyguard <iface> enable | disable` – toggle systemd oneshot service + `launch_on_start`
- `pyguard <iface> rename <new_iface>` – rename interface (state file, wg config, systemd unit)
- `pyguard <iface> add <peer_name> [<ip>]` – add peer (auto next free IP if not supplied)
- `pyguard <iface> remove <peer_name|index>` – remove peer by name or numeric index (from list)
- `pyguard <iface> list [--json]` – list peers (IP, handshake age, transfer, endpoint)
- `pyguard <iface> show server [--json]` – show server config summary
- `pyguard <iface> show <peer> [--save|--qr|--save-qr|--json]` – render client config; optionally save, display QR, save QR PNG
- `pyguard <iface> update <server-param> <value>` – update server setting (port, dns, public-ip, network)
- `pyguard <iface> update <peer> <param> <value>` – update peer (allowed-ips, ip, rename) or `rotate-keys`
- `pyguard <iface> dns_service <enable|disable>` – toggle built‑in DNS flag
- `pyguard <iface> allow_vpn_gateway <enable|disable>` – allow server to act as full gateway for peers
- `pyguard <iface> forward_to_docker_bridge <enable|disable>` – enable Docker bridge forwarding (use mainly inside container)
- `pyguard <iface> custom add|list|delete up|down ...` – manage additional PostUp/PostDown commands
- `pyguard <iface> delete interface` – delete this single interface (alias to top‑level delete form)
- `pyguard <iface> help` – show help

Notes & behavior:

- Peer QR output requires `qrencode` in PATH.
- `rotate-keys` (peer update) regenerates a peer keypair without altering its IP / AllowedIPs.
- Server `public_ip` can be hostname or IP; left empty becomes a placeholder in exported peer configs.
- `launch_on_start` is toggled by `enable` / `disable` (not by `launchAll`).

Peer configs live only in JSON state + generated wireguard conf fragments (render‑on‑demand). No external database.

---

## Web / API

The FastAPI app (`pyguard-api.py`) serves:

- `/login` – form login (sets access + refresh cookies)
- `/dashboard` – (protected) UI views
- JSON endpoints for interface & peer management (require JWT) – paths may evolve; inspect code for current routes.

Auth model:

- Access token (~15m) + refresh token (~24h) stored as httpOnly cookies.
- Middleware auto refreshes when access token expires (if refresh valid).

CORS:

- Configure with `PYGUARD_CORS_ORIGINS` (comma separated) or `*` (dev only).

---

## Embedded DNS (Optional)

`pyguard-dns.py` can answer A / AAAA records for peers & forward the rest upstream (default 1.1.1.1). Enable via interface flags (`dns_service`) and run under supervision (e.g. separate systemd unit or integrated process manager).

Benefits:

- Name peers (e.g. `laptop.wg0`) and resolve within the tunnel
- Local override before upstream resolution

---

## Docker Deployment

Userspace WireGuard (no kernel module required):

```bash
cd docker
docker compose -f docker-compose.wg-go.yml up --build -d
```

Environment variables (example compose):

- `PYGUARD_AUTOCREATE=1` – auto create `wg0` on first run
- `PYGUARD_EXTRA_INTERFACES=wg1,wg2` – pre-create additional interfaces
- `PYGUARD_WEB_DEBUG=1` – enable FastAPI debug

Expose / persist data by uncommenting volume mounts in `docker-compose.wg-go.yml`:

```yaml
		volumes:
			- ../data/pyguard:/etc/pyguard
			- ../data/wireguard:/etc/wireguard
			- ../data/logs:/var/log/pyguard
```

After container start, create an admin user (if not persisted) then visit `http://HOST:6656`.

---

## Configuration & Settings

`/etc/pyguard/settings` – simple key=value lines (auto created). Current enum:

- `allow_command_apply` (bool) – if true, API endpoints may apply firewall (UFW) rules.

Per interface JSON structure (simplified):

```jsonc
{
  "server": {
    "private_key": "...",
    "public_key": "...",
    "interface": "wg0",
    "port": 51820,
    "network": "10.0.0.0/24",
    "dns": "1.1.1.1",
    "public_ip": "1.2.3.4",
    "custom_post_up": [],
    "custom_post_down": []
  },
  "peers": { "alice": { "public_key": "...", "ip": "10.0.0.2" } },
  "launch_on_start": false,
  "dns_service": false,
  "forward_to_docker_bridge": false,
  "allow_vpn_gateway": false
}
```

---

## Security Notes

- Always run the public API behind TLS / reverse proxy (Caddy, Nginx, Traefik)
- Limit API binding to localhost or admin network; use firewall rules
- Rotate admin passwords periodically; bcrypt with per‑hash salt is used
- Protect `/etc/pyguard/secret.key` (permissions 600) – JWT signing key
- Consider setting more restrictive CORS origins in production
- Userspace `wireguard-go` is slower than kernel WireGuard; prefer kernel where possible

---

## Troubleshooting

- Interface not starting: check `/etc/wireguard/<iface>.conf` exists and `wg-quick up <iface>` output
- Peer cannot connect: confirm AllowedIPs in client config includes server network, server port reachable (UDP) & firewall open
- QR generation fails: install `qrencode` (Debian/Ubuntu: `apt install qrencode`)
- Web auth loops: delete cookies; verify `secret.key` stability (don’t delete while running)

---

## Development

```bash
git clone https://github.com/lead-afk/PyGuard.git
cd PyGuard
./init-project.sh  # venv + deps
source .venv/bin/activate
uvicorn pyguard-api:app --reload --port 6656
```

Run selected CLI operations (need root privileges when touching network):

```bash
sudo python pyguard.py getDefaults
sudo python pyguard.py init wg0
sudo python pyguard.py addPeer wg0 laptop
```

Code style: (lightweight) – please open a PR; formatting tools can be introduced later.

---

## Roadmap / Ideas

- multi users

---

## Contributing

PRs / issues welcome.

---

## License

Currently unlicensed (all rights reserved) unless a LICENSE file is added. Open an issue if you need explicit licensing terms.

---

## Disclaimer

Use at your own risk. Review code & security posture before exposing to untrusted networks.

## Special thanks

- K.P.
- B.A
- Copilot

## PS

If you own the background used in the page and wish to remove it contact me
