# HPE VNC wall (Standalone)

Reusable wall dashboard for many VNC hosts, grouped by any label (`group`), not tied to production lines.

## Features

- Token-based websockify proxy
- Optional dashboard login (session cookie)
- Built-in clients editor (`/clients`) with save/reload
- Dashboard with search + group filter
- Draggable columns control (slider + auto mode)
- Host selector panel (show/hide hosts per browser)
- Per-client VNC password
- Read-only **or** interactive mode
- Connect / disconnect / open in new tab
- Optional timed refresh and zoom

## Folder layout

- `wall_server.py`
- `config/config.json`
- `data/hosts.csv`
- `vendor/noVNC` (you provide this)

## Requirements

- Python 3.12+
- `websockify` Python module (installed by `setup_venv.bat`)
- noVNC extracted so this file exists:
  - `vnc_wall_standalone/vendor/noVNC/vnc_lite.html`

## Quick start

1. Create venv + install deps:
   - `setup_venv.bat`
2. Copy noVNC into:
   - `vendor/noVNC`
3. Copy config template:
   - `copy config\\config.example.json config\\config.json`
4. Edit:
   - `config/config.json`
   - `data/hosts.csv`
5. Run:
   - `run_wall.bat`

Open:

- Local: `http://127.0.0.1:8090`
- LAN: `http://<server-ip>:8090`
- Clients editor: `http://<server-ip>:8090/clients`

Optional (Windows service):

- `install_service.bat`
- `uninstall_service.bat`

## hosts.csv format

`group,name,host,port,enabled,password,note`

Example:

```csv
group,name,host,port,enabled,password,note
Servers,APP01,app01.lab.local,5900,1,,Main app node
Servers,DB01,db01.lab.local,5900,1,,Database node
Clients,PC-001,pc-001.lab.local,5900,1,,Operator workstation
```

Notes:

- `enabled=1` includes host
- `password` is optional and can be specific per client
- if password is empty, dashboard asks it at connect/open-tab time
- empty `port` uses `default_vnc_port`
- backward compatibility: `line` column is accepted as alias of `group`

## Clients editor

- URL: `/clients`
- Supports create/edit/delete rows and save directly to `data/hosts.csv`
- Updates enabled tokens immediately (no server restart required)
- Server starts even with 0 enabled hosts so first setup can be done from UI

## Favicon

- Preferred path: `assets/favicon.ico`
- Fallback path: `favicon.ico` (project root)
- URL served by app: `/favicon.ico`

## Config keys

- `default_view_only`: true = read-only default
- `allow_interactive`: show/hide interactive mode selector
- `preconnect`: connect all cards at startup (can be heavy)
- `vnc_password`: global fallback password (used when per-client password is empty)
- `auth_enabled`: enable login for dashboard/API hosts
- `auth_username`, `auth_password`: credentials used by `/login`
- `auth_cookie_name`: cookie name for authenticated session
- `auth_session_ttl_hours`: session duration (1..168 hours)
- `auth_session_secret`: optional signing secret (if empty, generated at startup)

## Dashboard auth

- Trusted LAN mode:
  - set `auth_enabled` to `false` (default)
- Protected mode:
  - set `auth_enabled` to `true`
  - set non-empty `auth_username` and `auth_password`
- Login page:
  - `http://<server-ip>:8090/login`
- Logout:
  - `http://<server-ip>:8090/logout`

## Publish checklist

- Remove real passwords from `config.json`
- Keep only sample hosts in `data/hosts.csv`
- Ship without `data/tokens.txt` (auto-generated at runtime)
