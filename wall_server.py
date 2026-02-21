#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import html
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config" / "config.json"
CONFIG_EXAMPLE_PATH = BASE_DIR / "config" / "config.example.json"
HOSTS_PATH = BASE_DIR / "data" / "hosts.csv"
HOSTS_EXAMPLE_PATH = BASE_DIR / "data" / "hosts.csv.example"
TOKENS_PATH = BASE_DIR / "data" / "tokens.txt"
FAVICON_ASSET_PATH = BASE_DIR / "assets" / "favicon.ico"
FAVICON_ROOT_PATH = BASE_DIR / "favicon.ico"
HOSTS_CSV_HEADERS = ["group", "name", "host", "port", "enabled", "password", "note"]


DEFAULT_CONFIG: dict[str, Any] = {
    "title": "HPE VNC wall",
    "listen_host": "0.0.0.0",
    "wall_port": 8090,
    "websockify_port": 6080,
    "novnc_web_root": "vendor/noVNC",
    "default_vnc_port": 5900,
    "vnc_password": "",
    "default_view_only": True,
    "allow_interactive": True,
    "resize": "remote",
    "quality": 6,
    "compression": 6,
    "preconnect": False,
    "auth_enabled": False,
    "auth_username": "admin",
    "auth_password": "",
    "auth_cookie_name": "vnc_wall_session",
    "auth_session_ttl_hours": 12,
    "auth_session_secret": "",
}


@dataclass
class HostEntry:
    token: str
    group: str
    name: str
    host: str
    port: int
    password: str
    note: str


def _clamp_int(value: Any, low: int, high: int, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(low, min(high, parsed))


def _config_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
        if lowered == "":
            return default
    return default


def _sanitize_cookie_name(value: Any) -> str:
    raw = str(value or "").strip()
    allowed = {"-", "_"}
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch in allowed)
    return cleaned or "vnc_wall_session"


def load_config() -> dict[str, Any]:
    config = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            config.update(raw)
    else:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(
            json.dumps(config, ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
        )
        if not CONFIG_EXAMPLE_PATH.exists():
            CONFIG_EXAMPLE_PATH.write_text(
                json.dumps(config, ensure_ascii=True, indent=2) + "\n",
                encoding="utf-8",
            )
    config["wall_port"] = _clamp_int(config.get("wall_port"), 1, 65535, 8090)
    config["websockify_port"] = _clamp_int(config.get("websockify_port"), 1, 65535, 6080)
    config["default_vnc_port"] = _clamp_int(config.get("default_vnc_port"), 1, 65535, 5900)
    config["quality"] = _clamp_int(config.get("quality"), 0, 9, 6)
    config["compression"] = _clamp_int(config.get("compression"), 0, 9, 6)
    # Backward compatibility: old key "view_only" still accepted.
    if "default_view_only" not in config:
        config["default_view_only"] = bool(config.get("view_only", True))
    config["default_view_only"] = _config_bool(config.get("default_view_only"), True)
    config["allow_interactive"] = _config_bool(config.get("allow_interactive"), True)
    config["preconnect"] = _config_bool(config.get("preconnect"), False)
    config["resize"] = str(config.get("resize") or "remote")
    config["listen_host"] = str(config.get("listen_host") or "0.0.0.0")
    raw_title = str(config.get("title") or "").strip()
    if raw_title.lower() in {"", "vnc wall", "hpe vnc wall"}:
        config["title"] = "HPE VNC wall"
    else:
        config["title"] = raw_title
    config["auth_enabled"] = _config_bool(config.get("auth_enabled"), False)
    config["auth_username"] = str(config.get("auth_username") or "admin").strip() or "admin"
    config["auth_password"] = str(config.get("auth_password") or "")
    config["auth_cookie_name"] = _sanitize_cookie_name(config.get("auth_cookie_name"))
    config["auth_session_ttl_hours"] = _clamp_int(config.get("auth_session_ttl_hours"), 1, 168, 12)
    config["auth_session_secret"] = str(config.get("auth_session_secret") or "").strip()
    config["_auth_secret_ephemeral"] = False
    if config["auth_enabled"] and not config["auth_session_secret"]:
        config["auth_session_secret"] = secrets.token_urlsafe(32)
        config["_auth_secret_ephemeral"] = True
    return config


def _tokenize(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in value.strip())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-") or "host"


def _is_enabled(raw: Any) -> bool:
    return _config_bool(raw, True)


@dataclass
class HostRow:
    group: str
    name: str
    host: str
    port: int
    enabled: bool
    password: str
    note: str


def ensure_hosts_files() -> None:
    if not HOSTS_PATH.exists():
        HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with HOSTS_PATH.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=HOSTS_CSV_HEADERS)
            writer.writeheader()
    if not HOSTS_EXAMPLE_PATH.exists():
        HOSTS_EXAMPLE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with HOSTS_EXAMPLE_PATH.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=HOSTS_CSV_HEADERS)
            writer.writeheader()
            writer.writerow(
                {
                    "group": "Servers",
                    "name": "APP01",
                    "host": "app01.lab.local",
                    "port": "5900",
                    "enabled": "1",
                    "password": "",
                    "note": "Main app node",
                }
            )
            writer.writerow(
                {
                    "group": "Servers",
                    "name": "DB01",
                    "host": "db01.lab.local",
                    "port": "5900",
                    "enabled": "1",
                    "password": "",
                    "note": "Database node",
                }
            )
            writer.writerow(
                {
                    "group": "Clients",
                    "name": "PC-001",
                    "host": "pc-001.lab.local",
                    "port": "5900",
                    "enabled": "1",
                    "password": "",
                    "note": "Operator workstation",
                }
            )


def load_host_rows(config: dict[str, Any]) -> list[HostRow]:
    ensure_hosts_files()
    rows: list[HostRow] = []
    default_port = int(config["default_vnc_port"])
    with HOSTS_PATH.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            host = str((row.get("host") or "").strip())
            if not host:
                continue
            group = str((row.get("group") or row.get("line") or "").strip()) or "Ungrouped"
            name = str((row.get("name") or "").strip()) or host
            note = str((row.get("note") or "").strip())
            password = str(row.get("password") or "")
            port = _clamp_int(row.get("port"), 1, 65535, default_port)
            enabled = _is_enabled(row.get("enabled"))
            rows.append(
                HostRow(
                    group=group,
                    name=name,
                    host=host,
                    port=port,
                    enabled=enabled,
                    password=password,
                    note=note,
                )
            )
    rows.sort(key=lambda r: (r.group.lower(), r.name.lower(), r.host.lower(), r.port))
    return rows


def build_enabled_hosts(rows: list[HostRow]) -> list[HostEntry]:
    result: list[HostEntry] = []
    used_tokens: set[str] = set()
    for row in rows:
        if not row.enabled:
            continue
        base_token = _tokenize(f"{row.group}-{row.name}-{row.host}")
        token = base_token
        suffix = 2
        while token in used_tokens:
            token = f"{base_token}-{suffix}"
            suffix += 1
        used_tokens.add(token)
        result.append(
            HostEntry(
                token=token,
                group=row.group,
                name=row.name,
                host=row.host,
                port=row.port,
                password=row.password,
                note=row.note,
            )
        )
    result.sort(key=lambda r: (r.group.lower(), r.name.lower(), r.host.lower(), r.port, r.token))
    return result


def write_hosts_csv(rows: list[HostRow]) -> None:
    HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HOSTS_PATH.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=HOSTS_CSV_HEADERS)
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {
                    "group": row.group,
                    "name": row.name,
                    "host": row.host,
                    "port": str(row.port),
                    "enabled": "1" if row.enabled else "0",
                    "password": row.password,
                    "note": row.note,
                }
            )


def host_row_to_payload(row: HostRow) -> dict[str, Any]:
    return {
        "group": row.group,
        "name": row.name,
        "host": row.host,
        "port": row.port,
        "enabled": row.enabled,
        "password": row.password,
        "note": row.note,
    }


def parse_host_rows_payload(config: dict[str, Any], payload: Any) -> tuple[list[HostRow] | None, str | None]:
    if not isinstance(payload, list):
        return None, "Expected an array of clients."
    if len(payload) > 5000:
        return None, "Too many clients in a single request (max 5000)."

    rows: list[HostRow] = []
    default_port = int(config["default_vnc_port"])
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            return None, f"Row {index}: expected an object."
        host = str(item.get("host") or "").strip()
        if not host:
            return None, f"Row {index}: host is required."
        group = str(item.get("group") or "").strip() or "Ungrouped"
        name = str(item.get("name") or "").strip() or host
        port = _clamp_int(item.get("port"), 1, 65535, default_port)
        enabled = _config_bool(item.get("enabled"), True)
        password = str(item.get("password") or "")
        note = str(item.get("note") or "")
        rows.append(
            HostRow(
                group=group,
                name=name,
                host=host,
                port=port,
                enabled=enabled,
                password=password,
                note=note,
            )
        )
    return rows, None


def write_tokens(hosts: list[HostEntry]) -> None:
    TOKENS_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{row.token}: {row.host}:{row.port}" for row in hosts]
    TOKENS_PATH.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _json_response(
    handler: BaseHTTPRequestHandler,
    payload: Any,
    status: int = 200,
    extra_headers: list[tuple[str, str]] | None = None,
) -> None:
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    if extra_headers:
        for header_name, header_value in extra_headers:
            handler.send_header(header_name, header_value)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _html_response(
    handler: BaseHTTPRequestHandler,
    body: str,
    status: int = 200,
    extra_headers: list[tuple[str, str]] | None = None,
) -> None:
    encoded = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    if extra_headers:
        for header_name, header_value in extra_headers:
            handler.send_header(header_name, header_value)
    handler.send_header("Content-Length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)


def _redirect(
    handler: BaseHTTPRequestHandler,
    location: str,
    extra_headers: list[tuple[str, str]] | None = None,
) -> None:
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Cache-Control", "no-store")
    if extra_headers:
        for header_name, header_value in extra_headers:
            handler.send_header(header_name, header_value)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def _cookie_header(name: str, value: str, max_age_seconds: int) -> str:
    parts = [
        f"{name}={value}",
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        f"Max-Age={max_age_seconds}",
    ]
    return "; ".join(parts)


def _clear_cookie_header(name: str) -> str:
    return "; ".join(
        [
            f"{name}=",
            "Path=/",
            "HttpOnly",
            "SameSite=Lax",
            "Max-Age=0",
        ]
    )


def _read_cookie(handler: BaseHTTPRequestHandler, name: str) -> str:
    raw = handler.headers.get("Cookie") or ""
    jar = SimpleCookie()
    try:
        jar.load(raw)
    except Exception:
        return ""
    morsel = jar.get(name)
    if morsel is None:
        return ""
    return str(morsel.value or "")


def _session_signing_key(config: dict[str, Any]) -> bytes:
    session_secret = str(config.get("auth_session_secret") or "")
    password = str(config.get("auth_password") or "")
    merged = f"{session_secret}|{password}".encode("utf-8")
    return hashlib.sha256(merged).digest()


def _build_session_token(config: dict[str, Any]) -> str:
    expiry = int(time.time()) + int(config["auth_session_ttl_hours"]) * 3600
    payload = {
        "u": str(config["auth_username"]),
        "e": expiry,
        "n": secrets.token_urlsafe(12),
    }
    payload_raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    payload_encoded = base64.urlsafe_b64encode(payload_raw).decode("ascii").rstrip("=")
    signature = hmac.new(
        _session_signing_key(config),
        payload_encoded.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_encoded}.{signature}"


def _verify_session_token(config: dict[str, Any], token: str) -> bool:
    if not token:
        return False
    try:
        payload_encoded, signature = token.rsplit(".", 1)
    except ValueError:
        return False
    expected = hmac.new(
        _session_signing_key(config),
        payload_encoded.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False
    padding = "=" * (-len(payload_encoded) % 4)
    try:
        payload_raw = base64.urlsafe_b64decode(payload_encoded + padding)
        payload = json.loads(payload_raw.decode("utf-8"))
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False
    username = str(payload.get("u") or "")
    expires_at = _clamp_int(payload.get("e"), 0, 4102444800, 0)
    if not hmac.compare_digest(username, str(config.get("auth_username") or "")):
        return False
    return int(time.time()) <= expires_at


def _credentials_ok(config: dict[str, Any], username: str, password: str) -> bool:
    expected_username = str(config.get("auth_username") or "")
    expected_password = str(config.get("auth_password") or "")
    return hmac.compare_digest(username, expected_username) and hmac.compare_digest(
        password,
        expected_password,
    )


def _validate_auth_config(config: dict[str, Any]) -> None:
    if not config.get("auth_enabled"):
        return
    if not str(config.get("auth_username") or "").strip():
        raise RuntimeError("auth_enabled=true requires a non-empty auth_username in config/config.json")
    if not str(config.get("auth_password") or ""):
        raise RuntimeError("auth_enabled=true requires a non-empty auth_password in config/config.json")


def build_login_html(config: dict[str, Any], error: str = "") -> str:
    title = html.escape(str(config.get("title") or "HPE VNC wall"))
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} - Login</title>
  <link rel="icon" href="/favicon.ico" sizes="any">
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: radial-gradient(circle at top, #12385a, #071a2a 60%, #05111a);
      color: #e7f2fb;
      font-family: Segoe UI, Tahoma, Arial, sans-serif;
    }}
    .panel {{
      width: min(92vw, 360px);
      border: 1px solid #2b5779;
      border-radius: 12px;
      background: linear-gradient(180deg, #0e2f49, #0a2338);
      padding: 18px;
      box-shadow: 0 14px 30px rgba(0, 0, 0, 0.35);
    }}
    h1 {{
      margin: 0 0 14px;
      font-size: 22px;
      letter-spacing: 0.2px;
    }}
    .hint {{
      margin: 0 0 14px;
      font-size: 13px;
      color: #a7c6dd;
    }}
    label {{
      display: block;
      margin-top: 10px;
      margin-bottom: 6px;
      font-size: 13px;
      color: #c8dff0;
    }}
    input {{
      width: 100%;
      border: 1px solid #3c6380;
      border-radius: 8px;
      background: #0f2b42;
      color: #e7f3fc;
      padding: 8px 10px;
      font-size: 14px;
    }}
    button {{
      margin-top: 14px;
      width: 100%;
      border: 1px solid #2f6289;
      border-radius: 8px;
      background: #17466b;
      color: #dff2ff;
      padding: 9px 10px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 600;
    }}
    button:hover {{
      background: #1d5683;
    }}
    .error {{
      margin-top: 12px;
      border: 1px solid #8e4f34;
      border-radius: 8px;
      padding: 8px 10px;
      color: #ffd6c8;
      background: #5f2f1d;
      font-size: 13px;
    }}
  </style>
</head>
<body>
  <form class="panel" method="post" action="/login" autocomplete="off">
    <h1>{title}</h1>
    <p class="hint">Authentication required</p>
    <label for="username">Username</label>
    <input id="username" name="username" type="text" required autofocus>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required>
    <button type="submit">Login</button>
    {error_html}
  </form>
</body>
</html>"""


def build_clients_html(config: dict[str, Any], rows: list[HostRow]) -> str:
    payload = [host_row_to_payload(row) for row in rows]
    title = html.escape(str(config.get("title") or "HPE VNC wall"))
    logout_button_html = (
        '<a class="btn secondary" href="/logout">Logout</a>' if config.get("auth_enabled") else ""
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} - Clients</title>
  <link rel="icon" href="/favicon.ico" sizes="any">
  <style>
    :root {{
      --bg: #071a2a;
      --panel: #0f2f4a;
      --line: #2a4f6d;
      --ink: #e7f2fb;
      --muted: #9fc0d6;
      --btn: #17466b;
      --btn-hover: #1d5683;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: linear-gradient(180deg, var(--bg), #06121d);
      color: var(--ink);
      font-family: Segoe UI, Tahoma, Arial, sans-serif;
    }}
    .topbar {{
      background: linear-gradient(180deg, #0d3d61, #0a2f4b);
      border-bottom: 1px solid #2b5779;
      padding: 10px 12px;
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .topbar h1 {{
      margin: 0;
      font-size: 20px;
      margin-right: 10px;
    }}
    .btn {{
      border: 1px solid #2f6289;
      border-radius: 6px;
      background: var(--btn);
      color: #dff2ff;
      padding: 6px 10px;
      font-size: 13px;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }}
    .btn:hover {{ background: var(--btn-hover); }}
    .btn.secondary {{
      background: #102f49;
      border-color: #2b5678;
      color: #bed8ea;
    }}
    .btn.warn {{
      border-color: #8e4f34;
      background: #5f2f1d;
      color: #ffd6c8;
    }}
    .meta {{
      margin-left: auto;
      font-size: 12px;
      color: #b9d6eb;
    }}
    .wrap {{
      padding: 10px;
      display: grid;
      gap: 10px;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: 12px;
      background: var(--panel);
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.18);
      overflow: hidden;
    }}
    .panel-head {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      font-size: 13px;
      color: var(--muted);
    }}
    .table-wrap {{
      overflow: auto;
      max-height: calc(100vh - 180px);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 1020px;
      font-size: 13px;
    }}
    thead th {{
      position: sticky;
      top: 0;
      z-index: 1;
      background: #123754;
      color: #dff1ff;
      text-align: left;
      padding: 8px;
      border-bottom: 1px solid var(--line);
      white-space: nowrap;
    }}
    tbody td {{
      border-bottom: 1px solid #1d4564;
      padding: 6px 8px;
      vertical-align: top;
    }}
    tbody tr:hover {{
      background: rgba(255, 255, 255, 0.03);
    }}
    input[type="text"], input[type="number"], input[type="password"], textarea {{
      width: 100%;
      border: 1px solid #3c6380;
      background: #0f2b42;
      color: #e7f3fc;
      border-radius: 6px;
      padding: 6px 8px;
      font-size: 13px;
    }}
    textarea {{
      min-height: 36px;
      resize: vertical;
    }}
    .status {{
      min-height: 20px;
      font-size: 13px;
      color: #b9d6eb;
      padding: 0 2px;
    }}
    .status.error {{
      color: #ffd6c8;
    }}
    .empty {{
      color: #9fc0d6;
      text-align: center;
      padding: 18px;
    }}
    .cell-enabled {{
      text-align: center;
      width: 70px;
    }}
    .cell-actions {{
      width: 88px;
      white-space: nowrap;
    }}
    .help {{
      margin: 0;
      padding: 0 2px;
      font-size: 12px;
      color: #9fc0d6;
    }}
    @media (max-width: 900px) {{
      .meta {{
        width: 100%;
        margin-left: 0;
      }}
      .table-wrap {{
        max-height: none;
      }}
    }}
    @keyframes fade-in-up {{
      from {{
        opacity: 0;
        transform: translateY(6px);
      }}
      to {{
        opacity: 1;
        transform: translateY(0);
      }}
    }}
    body {{
      font-family: Bahnschrift, "Segoe UI Variable", "Segoe UI", Tahoma, sans-serif;
      background:
        radial-gradient(1100px 360px at 15% -12%, rgba(46, 161, 255, 0.2), rgba(46, 161, 255, 0) 62%),
        radial-gradient(900px 320px at 88% -10%, rgba(31, 110, 168, 0.18), rgba(31, 110, 168, 0) 58%),
        linear-gradient(180deg, #071a2a, #05111a 72%);
    }}
    .topbar {{
      position: sticky;
      top: 0;
      z-index: 40;
      backdrop-filter: blur(7px);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.28);
    }}
    .panel {{
      background: linear-gradient(180deg, rgba(16, 47, 74, 0.94), rgba(11, 34, 53, 0.94));
      animation: fade-in-up 0.24s ease both;
    }}
    .btn {{
      transition: background 0.2s ease, transform 0.18s ease, box-shadow 0.2s ease;
    }}
    .btn:hover {{
      transform: translateY(-1px);
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.24);
    }}
    thead th {{
      background: linear-gradient(180deg, #184a70, #123754);
    }}
    tbody tr {{
      animation: fade-in-up 0.2s ease both;
    }}
  </style>
</head>
<body>
  <div class="topbar">
    <h1>{title} - Clients</h1>
    <a class="btn secondary" href="/">Back to Wall</a>
    <button class="btn" id="addRowBtn" type="button">Add client</button>
    <button class="btn" id="saveBtn" type="button">Save</button>
    <button class="btn secondary" id="reloadBtn" type="button">Reload</button>
    {logout_button_html}
    <div class="meta" id="metaInfo"></div>
  </div>

  <div class="wrap">
    <p class="help">Each row defines one VNC endpoint. Password can be set per client or via global config fallback.</p>
    <div class="status" id="statusBar"></div>
    <section class="panel">
      <div class="panel-head">Clients list (`group,name,host,port,enabled,password,note`)</div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Group</th>
              <th>Name</th>
              <th>Host</th>
              <th>Port</th>
              <th>Enabled</th>
              <th>Password</th>
              <th>Note</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="rowsBody"></tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    const DEFAULT_PORT = {int(config["default_vnc_port"])};
    const INITIAL_ROWS = {json.dumps(payload, ensure_ascii=True)};
    const rowsBody = document.getElementById('rowsBody');
    const statusBar = document.getElementById('statusBar');
    const metaInfo = document.getElementById('metaInfo');
    const addRowBtn = document.getElementById('addRowBtn');
    const saveBtn = document.getElementById('saveBtn');
    const reloadBtn = document.getElementById('reloadBtn');

    let rows = Array.isArray(INITIAL_ROWS) ? INITIAL_ROWS.map((row) => ({{ ...row }})) : [];

    function clampPort(value) {{
      const parsed = Number.parseInt(String(value || ''), 10);
      if (!Number.isFinite(parsed)) return DEFAULT_PORT;
      return Math.max(1, Math.min(65535, parsed));
    }}

    function normalizeRow(raw) {{
      const row = raw && typeof raw === 'object' ? raw : {{}};
      const host = String(row.host || '').trim();
      return {{
        group: String(row.group || 'Ungrouped').trim() || 'Ungrouped',
        name: String(row.name || '').trim(),
        host,
        port: clampPort(row.port),
        enabled: Boolean(row.enabled ?? true),
        password: String(row.password || ''),
        note: String(row.note || ''),
      }};
    }}

    function blankRow() {{
      return {{
        group: 'Ungrouped',
        name: '',
        host: '',
        port: DEFAULT_PORT,
        enabled: true,
        password: '',
        note: '',
      }};
    }}

    function setStatus(message, isError = false) {{
      statusBar.textContent = String(message || '');
      statusBar.classList.toggle('error', Boolean(isError));
    }}

    function refreshMeta() {{
      const configured = rows.length;
      const enabled = rows.filter((row) => row.enabled && String(row.host || '').trim() !== '').length;
      metaInfo.textContent = `${{configured}} configured | ${{enabled}} enabled`;
    }}

    function renderRows() {{
      rows = rows.map((row) => normalizeRow(row));
      rowsBody.innerHTML = '';
      if (rows.length === 0) {{
        const tr = document.createElement('tr');
        tr.innerHTML = '<td class="empty" colspan="8">No clients configured. Click "Add client".</td>';
        rowsBody.appendChild(tr);
        refreshMeta();
        return;
      }}

      for (let index = 0; index < rows.length; index += 1) {{
        const row = rows[index];
        const tr = document.createElement('tr');
        tr.dataset.index = String(index);
        tr.innerHTML = `
          <td><input type="text" data-field="group"></td>
          <td><input type="text" data-field="name"></td>
          <td><input type="text" data-field="host" placeholder="dns-or-ip"></td>
          <td><input type="number" min="1" max="65535" step="1" data-field="port"></td>
          <td class="cell-enabled"><input type="checkbox" data-field="enabled"></td>
          <td><input type="password" data-field="password" placeholder="optional"></td>
          <td><textarea data-field="note" rows="1"></textarea></td>
          <td class="cell-actions"><button class="btn warn" type="button" data-action="delete">Delete</button></td>
        `;
        const groupInput = tr.querySelector('input[data-field="group"]');
        const nameInput = tr.querySelector('input[data-field="name"]');
        const hostInput = tr.querySelector('input[data-field="host"]');
        const portInput = tr.querySelector('input[data-field="port"]');
        const enabledInput = tr.querySelector('input[data-field="enabled"]');
        const passwordInput = tr.querySelector('input[data-field="password"]');
        const noteInput = tr.querySelector('textarea[data-field="note"]');
        if (groupInput) groupInput.value = row.group;
        if (nameInput) nameInput.value = row.name;
        if (hostInput) hostInput.value = row.host;
        if (portInput) portInput.value = String(row.port);
        if (enabledInput) enabledInput.checked = Boolean(row.enabled);
        if (passwordInput) passwordInput.value = row.password;
        if (noteInput) noteInput.value = row.note;
        rowsBody.appendChild(tr);
      }}
      refreshMeta();
    }}

    function updateRowField(target) {{
      const tr = target.closest('tr[data-index]');
      if (!tr) return;
      const index = Number.parseInt(tr.dataset.index || '', 10);
      if (!Number.isFinite(index) || !rows[index]) return;
      const field = target.getAttribute('data-field') || '';
      if (!field) return;
      if (field === 'enabled' && target instanceof HTMLInputElement) {{
        rows[index].enabled = target.checked;
      }} else if (field === 'port') {{
        rows[index].port = clampPort(target.value);
      }} else {{
        rows[index][field] = String(target.value || '');
      }}
      refreshMeta();
    }}

    async function reloadRows() {{
      setStatus('Loading clients...');
      try {{
        const res = await fetch('/api/clients', {{ cache: 'no-store' }});
        const data = await res.json();
        if (!res.ok || !data.ok || !Array.isArray(data.clients)) {{
          throw new Error(String(data && data.error ? data.error : `HTTP ${{res.status}}`));
        }}
        rows = data.clients.map((row) => normalizeRow(row));
        renderRows();
        setStatus(`Loaded ${{rows.length}} clients.`);
      }} catch (err) {{
        setStatus(`Load failed: ${{err && err.message ? err.message : err}}`, true);
      }}
    }}

    async function saveRows() {{
      setStatus('Saving clients...');
      try {{
        const payload = rows.map((row) => normalizeRow(row));
        const res = await fetch('/api/clients', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ clients: payload }}),
        }});
        const data = await res.json();
        if (!res.ok || !data.ok) {{
          throw new Error(String(data && data.error ? data.error : `HTTP ${{res.status}}`));
        }}
        rows = Array.isArray(data.clients) ? data.clients.map((row) => normalizeRow(row)) : payload;
        renderRows();
        setStatus(`Saved. ${{data.enabled_hosts ?? 0}} enabled clients.`);
      }} catch (err) {{
        setStatus(`Save failed: ${{err && err.message ? err.message : err}}`, true);
      }}
    }}

    rowsBody.addEventListener('input', (ev) => {{
      const target = ev.target;
      if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) return;
      updateRowField(target);
    }});
    rowsBody.addEventListener('change', (ev) => {{
      const target = ev.target;
      if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) return;
      updateRowField(target);
    }});
    rowsBody.addEventListener('click', (ev) => {{
      const target = ev.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.getAttribute('data-action') !== 'delete') return;
      const tr = target.closest('tr[data-index]');
      if (!tr) return;
      const index = Number.parseInt(tr.dataset.index || '', 10);
      if (!Number.isFinite(index) || !rows[index]) return;
      rows.splice(index, 1);
      renderRows();
      setStatus('Client removed (not saved yet).');
    }});

    addRowBtn.addEventListener('click', () => {{
      rows.push(blankRow());
      renderRows();
      setStatus('Client row added.');
    }});
    saveBtn.addEventListener('click', saveRows);
    reloadBtn.addEventListener('click', reloadRows);

    renderRows();
    setStatus(`Loaded ${{rows.length}} clients.`);
  </script>
</body>
</html>"""


def build_wall_html(config: dict[str, Any], hosts: list[HostEntry]) -> str:
    hosts_payload = [
        {
            "token": row.token,
            "group": row.group,
            "name": row.name,
            "host": row.host,
            "port": row.port,
            "password": row.password,
            "note": row.note,
        }
        for row in hosts
    ]
    ui_config = {
        "title": config["title"],
        "websockifyPort": config["websockify_port"],
        "defaultViewOnly": config["default_view_only"],
        "allowInteractive": config["allow_interactive"],
        "authEnabled": config["auth_enabled"],
        "resize": config["resize"],
        "quality": config["quality"],
        "compression": config["compression"],
        "preconnect": config["preconnect"],
        "password": str(config.get("vnc_password") or ""),
    }
    title = str(config["title"])
    clients_button_html = '<a class="btn secondary" href="/clients">Clients</a>'
    logout_button_html = (
        '<a class="btn secondary" href="/logout">Logout</a>' if config.get("auth_enabled") else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <link rel="icon" href="/favicon.ico" sizes="any">
  <style>
    :root {{
      --bg: #071a2a;
      --bg-2: #0b2740;
      --panel: #0f2f4a;
      --panel-soft: #123754;
      --ink: #e7f2fb;
      --muted: #9fc0d6;
      --line: #2a4f6d;
      --accent: #2ea1ff;
      --accent-soft: #1f6ea8;
      --btn: #17466b;
      --btn-hover: #1d5683;
      --tile-h: 180px;
      --grid-min: 280px;
      --grid-cols: 1;
      --viewer-zoom: 1;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: linear-gradient(180deg, var(--bg), #06121d);
      color: var(--ink);
      font-family: Segoe UI, Tahoma, Arial, sans-serif;
    }}
    .topbar {{
      position: static;
      z-index: 2;
      background: linear-gradient(180deg, #0d3d61, #0a2f4b);
      border-bottom: 1px solid #2b5779;
      color: #fff;
      padding: 10px 12px;
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .topbar h1 {{
      margin: 0;
      font-size: 20px;
      margin-right: 12px;
      letter-spacing: 0.2px;
    }}
    .ctrl {{
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      color: #c7dff0;
    }}
    .ctrl input, .ctrl select {{
      border: 1px solid #3c6380;
      background: #0f2b42;
      color: #e7f3fc;
      border-radius: 6px;
      padding: 5px 8px;
      min-width: 120px;
      font-size: 13px;
    }}
    .ctrl input[type="range"] {{
      min-width: 140px;
      padding: 0;
    }}
    #gridDragLabel {{
      min-width: 58px;
      text-align: right;
      color: #b7d3e6;
      font-size: 12px;
    }}
    .ctrl input::placeholder {{ color: #9fb8cb; }}
    .btn {{
      border: 1px solid #2f6289;
      border-radius: 6px;
      background: var(--btn);
      color: #dff2ff;
      padding: 6px 10px;
      font-size: 13px;
      cursor: pointer;
    }}
    .btn:hover {{ background: var(--btn-hover); }}
    .btn.secondary {{
      background: #102f49;
      border-color: #2b5678;
      color: #bed8ea;
    }}
    .btn.secondary:hover {{ background: #163d5d; }}
    .btn.warn {{
      border-color: #8e4f34;
      background: #5f2f1d;
      color: #ffd6c8;
    }}
    .btn.warn:hover {{ background: #73402a; }}
    .btn:disabled {{
      opacity: 0.45;
      cursor: default;
    }}
    .topbar a.btn {{
      text-decoration: none;
      display: inline-flex;
      align-items: center;
    }}
    .meta {{
      font-size: 12px;
      color: #b9d6eb;
      margin-left: auto;
    }}
    .wrap {{
      padding: 10px;
      display: grid;
      gap: 10px;
    }}
    .empty-state {{
      border: 1px solid #2a4f6d;
      border-radius: 12px;
      background: #0f2f4a;
      padding: 20px;
      color: #d9ecfb;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.18);
      display: grid;
      gap: 10px;
      max-width: 680px;
    }}
    .empty-state h2 {{
      margin: 0;
      font-size: 22px;
      color: #e7f3fc;
    }}
    .empty-state p {{
      margin: 0;
      color: #b4d2e7;
      font-size: 14px;
      line-height: 1.4;
    }}
    .empty-state a.btn {{
      text-decoration: none;
      width: max-content;
    }}
    .line {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 10px;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.18);
    }}
    .line-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 8px;
    }}
    .line-head-main {{
      display: flex;
      align-items: baseline;
      gap: 8px;
    }}
    .line-head h2 {{
      margin: 0;
      font-size: 30px;
      color: #dff1ff;
    }}
    .line-head span,
    .line-head .line-stat {{
      color: var(--muted);
      font-size: 14px;
    }}
    .grid {{
      display: grid;
      gap: 8px;
      grid-template-columns: repeat(auto-fill, minmax(var(--grid-min), 1fr));
    }}
    body.grid-fixed .grid {{
      grid-template-columns: repeat(var(--grid-cols), minmax(0, 1fr));
    }}
    .card {{
      border: 1px solid var(--line);
      border-radius: 10px;
      background: var(--panel-soft);
      display: flex;
      flex-direction: column;
      min-height: calc(var(--tile-h) + 60px);
      overflow: hidden;
    }}
    .card-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      background: #123754;
      font-size: 12px;
    }}
    .card-title {{
      font-weight: 700;
      color: #e8f4fd;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 70%;
    }}
    .card-host {{
      color: #9fc0d6;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .viewer-slot {{
      position: relative;
      height: var(--tile-h);
      min-height: var(--tile-h);
      background: #0a0a0a;
      overflow: hidden;
    }}
    .viewer-scroll {{
      width: 100%;
      height: var(--tile-h);
      overflow: auto;
      overscroll-behavior: contain;
      scrollbar-color: #5d7e97 #0f1d2a;
      scrollbar-width: thin;
    }}
    .viewer-canvas {{
      position: relative;
      width: 100%;
      height: var(--tile-h);
      min-width: 100%;
      min-height: var(--tile-h);
    }}
    .viewer-slot iframe {{
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: var(--tile-h);
      border: 0;
      display: block;
      background: #0a0a0a;
      pointer-events: auto;
      transform: scale(var(--viewer-zoom));
      transform-origin: top left;
    }}
    .placeholder {{
      position: absolute;
      inset: 0;
      display: grid;
      place-items: center;
      color: #9aa7b3;
      font-size: 13px;
    }}
    .card-actions {{
      padding: 8px 10px;
      display: flex;
      gap: 6px;
      align-items: center;
      border-top: 1px solid var(--line);
      background: #123754;
    }}
    .host-note {{
      font-size: 11px;
      color: #98b8cd;
      margin-left: auto;
      max-width: 140px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .drawer {{
      position: fixed;
      inset: 0;
      z-index: 300;
      display: none;
    }}
    .drawer.open {{ display: block; }}
    .drawer-backdrop {{
      position: absolute;
      inset: 0;
      background: rgba(4, 10, 16, 0.62);
    }}
    .drawer-panel {{
      position: absolute;
      top: 0;
      right: 0;
      width: min(480px, 96vw);
      height: 100%;
      background: #0e2f4a;
      border-left: 1px solid #2a5576;
      display: flex;
      flex-direction: column;
      box-shadow: -20px 0 30px rgba(0, 0, 0, 0.35);
    }}
    .drawer-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px;
      border-bottom: 1px solid #2a5576;
      background: #103652;
    }}
    .drawer-head h3 {{
      margin: 0;
      font-size: 18px;
      color: #e5f3fe;
    }}
    .drawer-tools {{
      padding: 10px 12px;
      display: grid;
      gap: 8px;
      border-bottom: 1px solid #2a5576;
      background: #0f3350;
    }}
    .drawer-tools .row {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }}
    .drawer-tools input {{
      border: 1px solid #3c6380;
      background: #0f2b42;
      color: #e7f3fc;
      border-radius: 6px;
      padding: 6px 8px;
      font-size: 13px;
      width: 100%;
    }}
    .picker-list {{
      overflow: auto;
      padding: 8px 12px 14px;
      display: grid;
      gap: 4px;
    }}
    .picker-item {{
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 8px;
      border: 1px solid #224662;
      border-radius: 8px;
      background: #113754;
      font-size: 13px;
    }}
    .picker-item .line-tag {{
      font-size: 11px;
      color: #9ec0d7;
      border: 1px solid #356487;
      border-radius: 999px;
      padding: 1px 7px;
    }}
    .picker-item .host-id {{
      color: #d9ecfb;
      font-weight: 600;
      flex: 1;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .picker-item .host-meta {{
      color: #8fb3cb;
      max-width: 42%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 12px;
    }}
    .hidden {{ display: none !important; }}
    @media (max-width: 1200px) {{
      :root {{ --grid-min: 250px; }}
    }}
    @media (max-width: 760px) {{
      .topbar h1 {{ width: 100%; margin-right: 0; }}
      .meta {{ width: 100%; margin-left: 0; }}
      .line-head h2 {{ font-size: 24px; }}
      body.grid-fixed .grid {{ grid-template-columns: repeat(1, minmax(0, 1fr)); }}
    }}
    @keyframes rise-in {{
      from {{
        opacity: 0;
        transform: translateY(8px);
      }}
      to {{
        opacity: 1;
        transform: translateY(0);
      }}
    }}
    body {{
      font-family: Bahnschrift, "Segoe UI Variable", "Segoe UI", Tahoma, sans-serif;
      background:
        radial-gradient(1200px 420px at 10% -8%, rgba(46, 161, 255, 0.26), rgba(46, 161, 255, 0) 60%),
        radial-gradient(900px 400px at 90% -10%, rgba(25, 117, 188, 0.22), rgba(25, 117, 188, 0) 58%),
        linear-gradient(180deg, #061a2a, #040d15 72%);
    }}
    .topbar {{
      position: sticky;
      top: 0;
      backdrop-filter: blur(7px);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.28);
      border-bottom-color: rgba(137, 184, 217, 0.28);
      z-index: 30;
    }}
    .btn {{
      transition: background 0.2s ease, transform 0.18s ease, box-shadow 0.2s ease;
    }}
    .btn:hover {{
      transform: translateY(-1px);
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.24);
    }}
    .line {{
      background: linear-gradient(180deg, rgba(17, 52, 78, 0.92), rgba(13, 42, 63, 0.92));
      border-color: rgba(113, 162, 199, 0.34);
      animation: rise-in 0.26s ease both;
    }}
    .line-head {{
      border-bottom: 1px dashed rgba(117, 162, 196, 0.35);
      padding-bottom: 8px;
    }}
    .grid {{
      gap: 10px;
    }}
    .card {{
      border-color: rgba(98, 151, 190, 0.34);
      background:
        linear-gradient(180deg, rgba(20, 57, 84, 0.94), rgba(17, 49, 73, 0.94));
      box-shadow: inset 0 0 0 1px rgba(182, 215, 239, 0.06), 0 10px 20px rgba(0, 0, 0, 0.22);
      transition: transform 0.18s ease, box-shadow 0.2s ease;
      animation: rise-in 0.26s ease both;
    }}
    .card:hover {{
      transform: translateY(-2px);
      box-shadow: inset 0 0 0 1px rgba(182, 215, 239, 0.08), 0 14px 24px rgba(0, 0, 0, 0.26);
    }}
    .card-head {{
      background: linear-gradient(180deg, #16486d, #113a58);
    }}
    .viewer-slot {{
      background: linear-gradient(180deg, #0d2437, #0b1e2f);
    }}
    .empty-state {{
      background: linear-gradient(180deg, rgba(16, 47, 74, 0.95), rgba(12, 36, 56, 0.95));
    }}
  </style>
</head>
<body>
  <div class="topbar">
    <h1>{title}</h1>
    <div class="ctrl">
      <label for="groupFilter">Group</label>
      <select id="groupFilter"><option value="">All</option></select>
    </div>
    <div class="ctrl" id="modeControl">
      <label for="modeSelect">Mode</label>
      <select id="modeSelect">
        <option value="view">Read-only</option>
        <option value="control">Interactive</option>
      </select>
    </div>
    <div class="ctrl">
      <label for="searchBox">Search</label>
      <input id="searchBox" type="text" placeholder="host or name">
    </div>
    <div class="ctrl">
      <label for="gridDragRange">Columns</label>
      <input id="gridDragRange" type="range" min="1" max="6" step="1" value="3">
      <span id="gridDragLabel">Auto</span>
      <button class="btn secondary" id="gridAutoBtn" type="button">Auto</button>
    </div>
    <button class="btn secondary" id="openHostPickerBtn" type="button">Host Selector</button>
    <button class="btn" id="connectFilteredBtn" type="button">Connect filtered</button>
    <button class="btn warn" id="disconnectFilteredBtn" type="button">Disconnect filtered</button>
    {clients_button_html}
    {logout_button_html}
    <div class="ctrl">
      <label for="refreshEvery">Refresh</label>
      <select id="refreshEvery">
        <option value="0">OFF</option>
        <option value="10">10s</option>
        <option value="20">20s</option>
        <option value="30">30s</option>
        <option value="60">60s</option>
      </select>
    </div>
    <div class="ctrl">
      <label for="zoomRange">Zoom</label>
      <input id="zoomRange" type="range" min="20" max="300" step="5" value="100">
      <span id="zoomLabel">100%</span>
    </div>
    <div class="meta" id="metaInfo"></div>
  </div>

  <div class="wrap" id="wallRoot"></div>

  <aside id="hostDrawer" class="drawer">
    <div class="drawer-backdrop" data-close-drawer></div>
    <div class="drawer-panel">
      <div class="drawer-head">
        <h3>Host Selector</h3>
        <button class="btn secondary" id="closeHostPickerBtn" type="button">Close</button>
      </div>
      <div class="drawer-tools">
        <input id="hostPickerSearch" type="text" placeholder="Filter hosts in this panel">
        <div class="row">
          <button class="btn" id="enablePickerFilteredBtn" type="button">Enable filtered</button>
          <button class="btn warn" id="disablePickerFilteredBtn" type="button">Disable filtered</button>
          <button class="btn secondary" id="resetPickerBtn" type="button">Reset all</button>
        </div>
      </div>
      <div class="picker-list" id="hostPickerList"></div>
    </div>
  </aside>

  <script>
    const HOSTS = {json.dumps(hosts_payload, ensure_ascii=True)};
    const CFG = {json.dumps(ui_config, ensure_ascii=True)};
    const wsBase = `${{location.protocol}}//${{location.hostname}}:${{CFG.websockifyPort}}`;
    const visibleStoreKey = 'vnc_wall_visible_tokens_v1';
    const refreshStoreKey = 'vnc_wall_refresh_seconds_v1';
    const zoomStoreKey = 'vnc_wall_zoom_percent_v1';
    const gridStoreKey = 'vnc_wall_grid_cols_v1';

    const groupFilter = document.getElementById('groupFilter');
    const modeControl = document.getElementById('modeControl');
    const modeSelect = document.getElementById('modeSelect');
    const searchBox = document.getElementById('searchBox');
    const gridDragRange = document.getElementById('gridDragRange');
    const gridDragLabel = document.getElementById('gridDragLabel');
    const gridAutoBtn = document.getElementById('gridAutoBtn');
    const wallRoot = document.getElementById('wallRoot');
    const metaInfo = document.getElementById('metaInfo');
    const openHostPickerBtn = document.getElementById('openHostPickerBtn');
    const closeHostPickerBtn = document.getElementById('closeHostPickerBtn');
    const hostDrawer = document.getElementById('hostDrawer');
    const hostPickerSearch = document.getElementById('hostPickerSearch');
    const hostPickerList = document.getElementById('hostPickerList');
    const enablePickerFilteredBtn = document.getElementById('enablePickerFilteredBtn');
    const disablePickerFilteredBtn = document.getElementById('disablePickerFilteredBtn');
    const resetPickerBtn = document.getElementById('resetPickerBtn');
    const connectFilteredBtn = document.getElementById('connectFilteredBtn');
    const disconnectFilteredBtn = document.getElementById('disconnectFilteredBtn');
    const refreshEvery = document.getElementById('refreshEvery');
    const zoomRange = document.getElementById('zoomRange');
    const zoomLabel = document.getElementById('zoomLabel');
    const modeStoreKey = 'vnc_wall_mode_v1';
    const knownTokens = new Set(HOSTS.map((host) => host.token));
    const cardByToken = new Map();
    const groupSections = [];
    let refreshTimer = null;
    let refreshSeconds = 0;
    let gridMode = 'auto';
    let fixedGridCols = 3;
    const hostsWithPassword = HOSTS.filter((host) => String(host.password || '') !== '').length;
    const sessionPasswordByToken = new Map();

    function normalizeGridMode(rawValue) {{
      const raw = String(rawValue || 'auto').toLowerCase();
      if (raw === 'auto') return 'auto';
      const parsed = Number.parseInt(raw, 10);
      if (!Number.isFinite(parsed)) return 'auto';
      return String(Math.max(1, Math.min(6, parsed)));
    }}

    function loadGridMode() {{
      try {{
        const loaded = normalizeGridMode(localStorage.getItem(gridStoreKey) || 'auto');
        if (loaded !== 'auto') {{
          fixedGridCols = Number.parseInt(loaded, 10) || 3;
        }}
        return loaded;
      }} catch (_err) {{
        return 'auto';
      }}
    }}

    function updateGridControls() {{
      if (gridDragRange) gridDragRange.value = String(fixedGridCols);
      if (gridDragLabel) {{
        gridDragLabel.textContent = gridMode === 'auto' ? `Auto (${{fixedGridCols}})` : `${{fixedGridCols}} col`;
      }}
      if (gridAutoBtn) {{
        gridAutoBtn.textContent = gridMode === 'auto' ? 'Auto ON' : 'Auto';
      }}
    }}

    function gridModeLabel() {{
      return gridMode === 'auto' ? `grid auto (${{fixedGridCols}})` : `grid ${{fixedGridCols}} col`;
    }}

    function applyGridMode(nextMode) {{
      const normalized = normalizeGridMode(nextMode);
      if (normalized !== 'auto') {{
        fixedGridCols = Number.parseInt(normalized, 10) || fixedGridCols;
      }}
      gridMode = normalized;
      try {{
        localStorage.setItem(gridStoreKey, gridMode === 'auto' ? 'auto' : String(fixedGridCols));
      }} catch (_err) {{
      }}
      document.body.classList.toggle('grid-fixed', gridMode !== 'auto');
      document.documentElement.style.setProperty('--grid-cols', String(fixedGridCols));
      updateGridControls();
      for (const card of cardByToken.values()) {{
        card._syncViewport?.();
      }}
      applyFilters();
    }}

    function loadRuntimeMode() {{
      const fallback = CFG.defaultViewOnly ? 'view' : 'control';
      if (!CFG.allowInteractive) return 'view';
      try {{
        const raw = String(localStorage.getItem(modeStoreKey) || '').toLowerCase();
        if (raw === 'view' || raw === 'control') return raw;
      }} catch (_err) {{
      }}
      return fallback;
    }}

    let runtimeMode = loadRuntimeMode();

    function currentViewOnly() {{
      return runtimeMode !== 'control';
    }}

    function applyModeUI() {{
      if (!modeSelect || !modeControl) return;
      if (!CFG.allowInteractive) {{
        runtimeMode = 'view';
        modeSelect.value = 'view';
        modeSelect.disabled = true;
        modeControl.classList.add('hidden');
        return;
      }}
      modeControl.classList.remove('hidden');
      modeSelect.disabled = false;
      modeSelect.value = runtimeMode;
    }}

    function saveRuntimeMode(nextMode) {{
      runtimeMode = String(nextMode || 'view') === 'control' ? 'control' : 'view';
      localStorage.setItem(modeStoreKey, runtimeMode);
      applyModeUI();
    }}

    function requestPasswordForHost(host) {{
      const hostLabel = `${{host.name}} (${{host.host}}:${{host.port}})`;
      const entered = window.prompt(`VNC password for ${{hostLabel}}`, '');
      if (entered === null) return '';
      const password = String(entered || '');
      if (!password) return '';
      if (host && host.token) {{
        sessionPasswordByToken.set(String(host.token), password);
      }}
      return password;
    }}

    function effectivePassword(host) {{
      const token = String(host?.token || '');
      if (token) {{
        const sessionPwd = String(sessionPasswordByToken.get(token) || '');
        if (sessionPwd) return sessionPwd;
      }}
      const hostPwd = String(host?.password || '');
      if (hostPwd) return hostPwd;
      return String(CFG.password || '');
    }}

    const frameParams = (token, password) => {{
      const p = new URLSearchParams();
      p.set('autoconnect', 'true');
      p.set('reconnect', 'true');
      p.set('path', `websockify?token=${{token}}`);
      p.set('title', String(CFG.title || 'HPE VNC wall'));
      p.set('resize', CFG.resize || 'remote');
      p.set('quality', String(CFG.quality ?? 6));
      p.set('compression', String(CFG.compression ?? 6));
      p.set('show_dot', 'true');
      if (currentViewOnly()) p.set('view_only', 'true');
      p.set('shared', currentViewOnly() ? 'true' : 'false');
      if (password) p.set('password', password);
      return `${{wsBase}}/vnc_lite.html?${{p.toString()}}`;
    }};

    function loadVisibleTokens() {{
      try {{
        const raw = localStorage.getItem(visibleStoreKey);
        if (!raw) return new Set(knownTokens);
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return new Set(knownTokens);
        const set = new Set(parsed.filter((token) => knownTokens.has(token)));
        return set.size ? set : new Set(knownTokens);
      }} catch (_err) {{
        return new Set(knownTokens);
      }}
    }}

    let visibleTokens = loadVisibleTokens();

    function saveVisibleTokens() {{
      localStorage.setItem(visibleStoreKey, JSON.stringify(Array.from(visibleTokens)));
    }}

    function isVisibleToken(token) {{
      return visibleTokens.has(token);
    }}

    function pickerMatches(host) {{
      const q = (hostPickerSearch.value || '').trim().toLowerCase();
      if (!q) return true;
      return (`${{host.group}} ${{host.name}} ${{host.host}}`).toLowerCase().includes(q);
    }}

    function renderHostPicker() {{
      hostPickerList.innerHTML = '';
      const hosts = [...HOSTS].sort((a, b) => {{
        const groupDiff = String(a.group).localeCompare(String(b.group), undefined, {{ numeric: true }});
        if (groupDiff !== 0) return groupDiff;
        const nameDiff = String(a.name).localeCompare(String(b.name), undefined, {{ numeric: true }});
        if (nameDiff !== 0) return nameDiff;
        return String(a.host).localeCompare(String(b.host), undefined, {{ numeric: true }});
      }});
      for (const host of hosts) {{
        if (!pickerMatches(host)) continue;
        const row = document.createElement('label');
        row.className = 'picker-item';
        row.innerHTML = `
          <input type="checkbox" data-token="${{host.token}}" ${{isVisibleToken(host.token) ? 'checked' : ''}}>
          <span class="line-tag">${{host.group}}</span>
          <span class="host-id" title="${{host.name}}">${{host.name}}</span>
          <span class="host-meta" title="${{host.host}}:${{host.port}}">${{host.host}}:${{host.port}}</span>
        `;
        hostPickerList.appendChild(row);
      }}
    }}

    function toggleDrawer(open) {{
      hostDrawer.classList.toggle('open', Boolean(open));
      if (open) {{
        renderHostPicker();
        setTimeout(() => hostPickerSearch.focus(), 0);
      }}
    }}

    function buildCard(host) {{
      const card = document.createElement('article');
      card.className = 'card';
      card.dataset.token = host.token;
      card.dataset.group = host.group;
      card.dataset.search = `${{host.group}} ${{host.name}} ${{host.host}} ${{host.note || ''}}`.toLowerCase();

      const head = document.createElement('div');
      head.className = 'card-head';
      head.innerHTML = `
        <div class="card-title" title="${{host.name}}">${{host.name}}</div>
        <div class="card-host" title="${{host.host}}:${{host.port}}">${{host.host}}:${{host.port}}</div>
      `;
      card.appendChild(head);

      const viewerSlot = document.createElement('div');
      viewerSlot.className = 'viewer-slot';
      viewerSlot.innerHTML = '<div class="placeholder">Disconnected</div>';
      card.appendChild(viewerSlot);

      const actions = document.createElement('div');
      actions.className = 'card-actions';
      const connectBtn = document.createElement('button');
      connectBtn.type = 'button';
      connectBtn.className = 'btn';
      connectBtn.textContent = 'Connect';
      const disconnectBtn = document.createElement('button');
      disconnectBtn.type = 'button';
      disconnectBtn.className = 'btn';
      disconnectBtn.textContent = 'Disconnect';
      disconnectBtn.disabled = true;
      const openTabBtn = document.createElement('button');
      openTabBtn.type = 'button';
      openTabBtn.className = 'btn secondary';
      openTabBtn.textContent = 'Open tab';
      actions.appendChild(connectBtn);
      actions.appendChild(disconnectBtn);
      actions.appendChild(openTabBtn);
      if (host.note) {{
        const note = document.createElement('span');
        note.className = 'host-note';
        note.title = host.note;
        note.textContent = host.note;
        actions.appendChild(note);
      }}
      card.appendChild(actions);

      const syncViewerViewport = () => {{
        const viewerScroll = viewerSlot.querySelector('.viewer-scroll');
        const viewerCanvas = viewerSlot.querySelector('.viewer-canvas');
        const frame = viewerSlot.querySelector('iframe');
        if (!viewerScroll || !viewerCanvas || !frame) return;

        const raw = String(getComputedStyle(document.documentElement).getPropertyValue('--viewer-zoom') || '1').trim();
        const parsed = Number.parseFloat(raw);
        const scale = Number.isFinite(parsed) ? Math.max(0.2, Math.min(3.0, parsed)) : 1.0;
        const viewportW = Math.max(1, viewerScroll.clientWidth);
        const viewportH = Math.max(1, viewerScroll.clientHeight);

        let canvasW = viewportW;
        let canvasH = viewportH;
        let frameW = viewportW;
        let frameH = viewportH;

        if (scale >= 1) {{
          canvasW = Math.round(viewportW * scale);
          canvasH = Math.round(viewportH * scale);
        }} else {{
          frameW = Math.round(viewportW / scale);
          frameH = Math.round(viewportH / scale);
        }}

        viewerCanvas.style.width = `${{canvasW}}px`;
        viewerCanvas.style.height = `${{canvasH}}px`;
        frame.style.width = `${{frameW}}px`;
        frame.style.height = `${{frameH}}px`;
      }};

      const connect = () => {{
        let password = effectivePassword(host);
        if (!password) {{
          password = requestPasswordForHost(host);
        }}
        if (!password) {{
          alert('Password required. Set per-client password in /clients or insert it when requested.');
          return;
        }}
        if (viewerSlot.querySelector('iframe')) return;
        viewerSlot.innerHTML = '';
        const viewerScroll = document.createElement('div');
        viewerScroll.className = 'viewer-scroll';
        const viewerCanvas = document.createElement('div');
        viewerCanvas.className = 'viewer-canvas';
        const frame = document.createElement('iframe');
        frame.loading = 'lazy';
        frame.allow = 'clipboard-read; clipboard-write';
        frame.tabIndex = -1;
        frame.src = `${{frameParams(host.token, password)}}&ts=${{Date.now()}}`;
        viewerCanvas.appendChild(frame);
        viewerScroll.appendChild(viewerCanvas);
        viewerSlot.appendChild(viewerScroll);
        syncViewerViewport();
        connectBtn.disabled = true;
        disconnectBtn.disabled = false;
      }};

      const disconnect = () => {{
        viewerSlot.innerHTML = '<div class="placeholder">Disconnected</div>';
        connectBtn.disabled = false;
        disconnectBtn.disabled = true;
      }};

      connectBtn.addEventListener('click', connect);
      disconnectBtn.addEventListener('click', disconnect);
      openTabBtn.addEventListener('click', () => {{
        let password = effectivePassword(host);
        if (!password) {{
          password = requestPasswordForHost(host);
        }}
        if (!password) {{
          alert('Password required. Set per-client password in /clients or insert it when requested.');
          return;
        }}
        const targetUrl = `${{frameParams(host.token, password)}}&ts=${{Date.now()}}`;
        window.open(targetUrl, '_blank', 'noopener');
      }});

      if (CFG.preconnect) {{
        connect();
      }}

      card._connect = connect;
      card._disconnect = disconnect;
      card._refresh = () => {{
        const frame = viewerSlot.querySelector('iframe');
        if (!frame) {{
          connect();
          return;
        }}
        const viewerScroll = viewerSlot.querySelector('.viewer-scroll');
        const prevLeft = viewerScroll ? viewerScroll.scrollLeft : 0;
        const prevTop = viewerScroll ? viewerScroll.scrollTop : 0;
        syncViewerViewport();
        frame.src = `${{frameParams(host.token, effectivePassword(host))}}&ts=${{Date.now()}}`;
        if (viewerScroll) {{
          frame.addEventListener('load', () => {{
            viewerScroll.scrollLeft = prevLeft;
            viewerScroll.scrollTop = prevTop;
          }}, {{ once: true }});
        }}
      }};
      card._syncViewport = syncViewerViewport;
      card._host = host;
      return card;
    }}

    function buildWall() {{
      if (HOSTS.length === 0) {{
        const empty = document.createElement('section');
        empty.className = 'empty-state';
        empty.innerHTML = `
          <h2>No enabled clients configured</h2>
          <p>Open the clients editor to add your first endpoints (group, host, port, password, note).</p>
          <a class="btn" href="/clients">Open Clients Editor</a>
        `;
        wallRoot.appendChild(empty);
        updateMeta(0);
        return;
      }}
      const byGroup = new Map();
      for (const host of HOSTS) {{
        const key = String(host.group || 'Ungrouped');
        if (!byGroup.has(key)) byGroup.set(key, []);
        byGroup.get(key).push(host);
      }}
      const groupKeys = Array.from(byGroup.keys()).sort((a, b) => a.localeCompare(b, undefined, {{ numeric: true }}));

      for (const group of groupKeys) {{
        const opt = document.createElement('option');
        opt.value = group;
        opt.textContent = group;
        groupFilter.appendChild(opt);

        const section = document.createElement('section');
        section.className = 'line';
        section.dataset.group = group;

        const head = document.createElement('header');
        head.className = 'line-head';
        head.innerHTML = `
          <div class="line-head-main">
            <h2>${{group}}</h2>
            <span>${{byGroup.get(group).length}} hosts</span>
          </div>
          <div class="line-stat">0 visible</div>
        `;
        section.appendChild(head);
        section._lineStat = head.querySelector('.line-stat');

        const grid = document.createElement('div');
        grid.className = 'grid';
        for (const host of byGroup.get(group)) {{
          const card = buildCard(host);
          cardByToken.set(host.token, card);
          grid.appendChild(card);
        }}
        section._grid = grid;
        section.appendChild(grid);
        wallRoot.appendChild(section);
        groupSections.push(section);
      }}
      updateMeta();
    }}

    function visibleCards() {{
      const cards = Array.from(document.querySelectorAll('.card'));
      return cards.filter((card) => !card.classList.contains('hidden') && !card.closest('.line').classList.contains('hidden'));
    }}

    function applyFilters() {{
      const groupValue = (groupFilter.value || '').toLowerCase();
      const search = (searchBox.value || '').trim().toLowerCase();
      let visibleCount = 0;
      for (const section of groupSections) {{
        const sectionKey = (section.dataset.group || '').toLowerCase();
        let sectionVisible = groupValue === '' || sectionKey === groupValue;
        const cards = Array.from(section.querySelectorAll('.card'));
        let visibleInSection = 0;
        for (const card of cards) {{
          let show = sectionVisible;
          if (show && !isVisibleToken(card.dataset.token || '')) {{
            show = false;
          }}
          if (show && search) {{
            show = card.dataset.search.includes(search);
          }}
          card.classList.toggle('hidden', !show);
          if (show) {{
            visibleCount += 1;
            visibleInSection += 1;
          }}
        }}
        section.classList.toggle('hidden', visibleInSection === 0);
        if (section._lineStat) {{
          section._lineStat.textContent = `${{visibleInSection}} / ${{cards.length}} visible`;
        }}
        if (section._grid) {{
          if (gridMode === 'auto') {{
            section._grid.style.removeProperty('grid-template-columns');
          }} else {{
            const cols = Math.max(1, Math.min(fixedGridCols, visibleInSection || 1));
            section._grid.style.gridTemplateColumns = `repeat(${{cols}}, minmax(0, 1fr))`;
          }}
        }}
      }}
      updateMeta(visibleCount);
    }}

    function updateMeta(visibleCount) {{
      const shown = typeof visibleCount === 'number' ? visibleCount : visibleCards().length;
      let pwdState = 'pwd missing';
      const sessionPwdCount = sessionPasswordByToken.size;
      if (sessionPwdCount > 0) pwdState = `pwd session ${{sessionPwdCount}}`;
      else if (hostsWithPassword > 0) pwdState = `pwd per-host ${{hostsWithPassword}}`;
      else if (String(CFG.password || '')) pwdState = 'pwd default';
      const refreshState = refreshSeconds > 0 ? `refresh ${{refreshSeconds}}s` : 'refresh off';
      const modeState = currentViewOnly() ? 'mode read-only' : 'mode interactive';
      const gridState = gridModeLabel();
      metaInfo.textContent = `${{shown}} shown / ${{HOSTS.length}} total | ${{visibleTokens.size}} enabled | ${{pwdState}} | ${{modeState}} | ${{gridState}} | ${{refreshState}}`;
    }}

    function reconnectConnectedVisible() {{
      for (const card of visibleCards()) {{
        const frame = card.querySelector('.viewer-slot iframe');
        if (!frame) continue;
        card._disconnect?.();
        card._connect?.();
      }}
    }}

    function applyRefreshMode(seconds) {{
      refreshSeconds = Math.max(0, Number.parseInt(String(seconds || '0'), 10) || 0);
      if (refreshTimer) {{
        clearInterval(refreshTimer);
        refreshTimer = null;
      }}
      if (refreshSeconds > 0) {{
        for (const card of visibleCards()) {{
          card._refresh?.();
        }}
        refreshTimer = setInterval(() => {{
          for (const card of visibleCards()) {{
            card._refresh?.();
          }}
        }}, refreshSeconds * 1000);
      }}
      localStorage.setItem(refreshStoreKey, String(refreshSeconds));
      refreshEvery.value = String(refreshSeconds);
      updateMeta();
    }}

    function applyViewerZoom(rawPercent) {{
      const pct = Math.max(20, Math.min(300, Number.parseInt(String(rawPercent || '100'), 10) || 100));
      const factor = (pct / 100).toFixed(2);
      document.documentElement.style.setProperty('--viewer-zoom', factor);
      zoomRange.value = String(pct);
      zoomLabel.textContent = `${{pct}}%`;
      localStorage.setItem(zoomStoreKey, String(pct));
      for (const card of cardByToken.values()) {{
        card._syncViewport?.();
      }}
    }}

    connectFilteredBtn.addEventListener('click', () => {{
      for (const card of visibleCards()) {{
        card._connect?.();
      }}
    }});
    disconnectFilteredBtn.addEventListener('click', () => {{
      for (const card of visibleCards()) {{
        card._disconnect?.();
      }}
    }});

    openHostPickerBtn.addEventListener('click', () => toggleDrawer(true));
    closeHostPickerBtn.addEventListener('click', () => toggleDrawer(false));
    hostDrawer.querySelectorAll('[data-close-drawer]').forEach((el) => {{
      el.addEventListener('click', () => toggleDrawer(false));
    }});

    hostPickerSearch.addEventListener('input', renderHostPicker);
    hostPickerList.addEventListener('change', (ev) => {{
      const target = ev.target;
      if (!(target instanceof HTMLInputElement)) return;
      if (!target.matches('input[type="checkbox"][data-token]')) return;
      const token = target.getAttribute('data-token') || '';
      if (!knownTokens.has(token)) return;
      if (target.checked) visibleTokens.add(token);
      else visibleTokens.delete(token);
      saveVisibleTokens();
      applyFilters();
    }});

    enablePickerFilteredBtn.addEventListener('click', () => {{
      for (const host of HOSTS) {{
        if (!pickerMatches(host)) continue;
        visibleTokens.add(host.token);
      }}
      saveVisibleTokens();
      renderHostPicker();
      applyFilters();
    }});
    disablePickerFilteredBtn.addEventListener('click', () => {{
      for (const host of HOSTS) {{
        if (!pickerMatches(host)) continue;
        visibleTokens.delete(host.token);
      }}
      saveVisibleTokens();
      renderHostPicker();
      applyFilters();
    }});
    resetPickerBtn.addEventListener('click', () => {{
      visibleTokens = new Set(knownTokens);
      saveVisibleTokens();
      renderHostPicker();
      applyFilters();
    }});

    groupFilter.addEventListener('change', applyFilters);
    searchBox.addEventListener('input', applyFilters);
    gridDragRange.addEventListener('input', () => {{
      const nextCols = Math.max(1, Math.min(6, Number.parseInt(gridDragRange.value || '3', 10) || 3));
      applyGridMode(String(nextCols));
    }});
    gridAutoBtn.addEventListener('click', () => {{
      if (gridMode === 'auto') {{
        applyGridMode(String(fixedGridCols));
      }} else {{
        applyGridMode('auto');
      }}
    }});
    modeSelect.addEventListener('change', () => {{
      saveRuntimeMode(modeSelect.value);
      updateMeta();
      const hasOpen = document.querySelector('.viewer-slot iframe') !== null;
      if (hasOpen) {{
        const ok = confirm('Reconnect visible sessions with the selected mode?');
        if (ok) reconnectConnectedVisible();
      }}
    }});
    refreshEvery.addEventListener('change', () => {{
      applyRefreshMode(refreshEvery.value);
    }});
    zoomRange.addEventListener('input', () => {{
      applyViewerZoom(zoomRange.value);
    }});
    window.addEventListener('resize', () => {{
      for (const card of cardByToken.values()) {{
        card._syncViewport?.();
      }}
    }});

    gridMode = loadGridMode();
    buildWall();
    applyModeUI();
    applyGridMode(gridMode);
    renderHostPicker();
    applyRefreshMode(localStorage.getItem(refreshStoreKey) || '0');
    applyViewerZoom(localStorage.getItem(zoomStoreKey) || '100');
    applyFilters();
  </script>
</body>
</html>"""


def make_handler(
    config: dict[str, Any],
    state: dict[str, Any],
    state_lock: threading.RLock,
):
    auth_enabled = bool(config.get("auth_enabled"))
    auth_cookie_name = str(config.get("auth_cookie_name") or "vnc_wall_session")
    auth_session_max_age = int(config.get("auth_session_ttl_hours") or 12) * 3600

    class WallHandler(BaseHTTPRequestHandler):
        server_version = "VNCWall/1.0"

        def _is_authenticated(self) -> bool:
            if not auth_enabled:
                return True
            token = _read_cookie(self, auth_cookie_name)
            return _verify_session_token(config, token)

        def _serve_login(self, error: str = "", status: int = 200) -> None:
            _html_response(self, build_login_html(config, error=error), status=status)

        def _serve_favicon(self) -> None:
            icon_path = FAVICON_ASSET_PATH if FAVICON_ASSET_PATH.exists() else FAVICON_ROOT_PATH
            if not icon_path.exists():
                self.send_response(204)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = icon_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self.send_header("Cache-Control", "public, max-age=300")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _snapshot_rows(self) -> list[HostRow]:
            with state_lock:
                return list(state.get("rows") or [])

        def _snapshot_enabled_hosts(self) -> list[HostEntry]:
            with state_lock:
                return list(state.get("enabled_hosts") or [])

        def _apply_rows(self, rows: list[HostRow]) -> tuple[int, int]:
            enabled_hosts = build_enabled_hosts(rows)
            with state_lock:
                write_hosts_csv(rows)
                write_tokens(enabled_hosts)
                state["rows"] = list(rows)
                state["enabled_hosts"] = list(enabled_hosts)
                state["updated_at"] = int(time.time())
            return len(rows), len(enabled_hosts)

        def _read_json_body(self, max_bytes: int = 2 * 1024 * 1024) -> tuple[Any, str | None]:
            content_length = _clamp_int(self.headers.get("Content-Length"), 0, max_bytes, 0)
            raw = self.rfile.read(content_length) if content_length > 0 else b""
            try:
                payload = json.loads(raw.decode("utf-8") if raw else "{}")
            except Exception:
                return None, "Invalid JSON body."
            return payload, None

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/favicon.ico":
                self._serve_favicon()
                return
            if path == "/login":
                if self._is_authenticated():
                    _redirect(self, "/")
                    return
                self._serve_login()
                return
            if path == "/logout":
                target = "/login" if auth_enabled else "/"
                _redirect(
                    self,
                    target,
                    extra_headers=[
                        ("Set-Cookie", _clear_cookie_header(auth_cookie_name)),
                    ],
                )
                return
            if path in ("/", "/index.html"):
                if not self._is_authenticated():
                    _redirect(self, "/login")
                    return
                enabled_hosts = self._snapshot_enabled_hosts()
                _html_response(self, build_wall_html(config, enabled_hosts))
                return
            if path == "/clients":
                if not self._is_authenticated():
                    _redirect(self, "/login")
                    return
                rows = self._snapshot_rows()
                _html_response(self, build_clients_html(config, rows))
                return
            if path == "/api/hosts":
                if not self._is_authenticated():
                    _json_response(self, {"ok": False, "error": "Unauthorized"}, status=401)
                    return
                enabled_hosts = self._snapshot_enabled_hosts()
                payload = [
                    {
                        "token": row.token,
                        "group": row.group,
                        "name": row.name,
                        "host": row.host,
                        "port": row.port,
                        "note": row.note,
                    }
                    for row in enabled_hosts
                ]
                _json_response(self, payload)
                return
            if path == "/api/clients":
                if not self._is_authenticated():
                    _json_response(self, {"ok": False, "error": "Unauthorized"}, status=401)
                    return
                rows = self._snapshot_rows()
                enabled_hosts = self._snapshot_enabled_hosts()
                _json_response(
                    self,
                    {
                        "ok": True,
                        "clients": [host_row_to_payload(row) for row in rows],
                        "configured_hosts": len(rows),
                        "enabled_hosts": len(enabled_hosts),
                    },
                )
                return
            if path == "/health":
                rows = self._snapshot_rows()
                enabled_hosts = self._snapshot_enabled_hosts()
                _json_response(
                    self,
                    {
                        "ok": True,
                        "hosts": len(enabled_hosts),
                        "configured_hosts": len(rows),
                        "enabled_hosts": len(enabled_hosts),
                        "auth_enabled": auth_enabled,
                    },
                )
                return
            _json_response(self, {"ok": False, "error": "Not Found"}, status=404)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/login":
                if not auth_enabled:
                    _redirect(self, "/")
                    return

                max_bytes = 16 * 1024
                content_length = _clamp_int(self.headers.get("Content-Length"), 0, max_bytes, 0)
                body_raw = self.rfile.read(content_length) if content_length > 0 else b""
                try:
                    form_data = parse_qs(body_raw.decode("utf-8"), keep_blank_values=True)
                except Exception:
                    form_data = {}
                username = str((form_data.get("username") or [""])[0]).strip()
                password = str((form_data.get("password") or [""])[0])
                if _credentials_ok(config, username, password):
                    session_token = _build_session_token(config)
                    _redirect(
                        self,
                        "/",
                        extra_headers=[
                            (
                                "Set-Cookie",
                                _cookie_header(
                                    auth_cookie_name,
                                    session_token,
                                    auth_session_max_age,
                                ),
                            )
                        ],
                    )
                    return
                self._serve_login(error="Invalid username or password.", status=401)
                return

            if path == "/api/clients":
                if not self._is_authenticated():
                    _json_response(self, {"ok": False, "error": "Unauthorized"}, status=401)
                    return
                payload, parse_error = self._read_json_body()
                if parse_error:
                    _json_response(self, {"ok": False, "error": parse_error}, status=400)
                    return
                if isinstance(payload, dict):
                    raw_clients = payload.get("clients")
                else:
                    raw_clients = payload
                rows, error = parse_host_rows_payload(config, raw_clients)
                if error:
                    _json_response(self, {"ok": False, "error": error}, status=400)
                    return
                assert rows is not None
                configured_count, enabled_count = self._apply_rows(rows)
                _json_response(
                    self,
                    {
                        "ok": True,
                        "clients": [host_row_to_payload(row) for row in rows],
                        "configured_hosts": configured_count,
                        "enabled_hosts": enabled_count,
                    },
                )
                return

            _json_response(self, {"ok": False, "error": "Not Found"}, status=404)

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stdout.write("[wall] " + (fmt % args) + "\n")

    return WallHandler


def start_websockify(config: dict[str, Any], tokens_file: Path) -> subprocess.Popen:
    novnc_root = Path(str(config["novnc_web_root"]))
    if not novnc_root.is_absolute():
        novnc_root = BASE_DIR / novnc_root

    def _has_novnc_assets(path: Path) -> bool:
        return path.exists() and (path / "vnc_lite.html").exists()

    if not _has_novnc_assets(novnc_root):
        candidates: list[Path] = []
        vendor_dir = BASE_DIR / "vendor"
        if vendor_dir.exists():
            for child in vendor_dir.iterdir():
                if child.is_dir() and _has_novnc_assets(child):
                    candidates.append(child)

        for fallback in (
            BASE_DIR / "vendor" / "noVNC",
            BASE_DIR / "vendor" / "novnc",
            BASE_DIR / "noVNC",
            BASE_DIR / "novnc",
        ):
            if _has_novnc_assets(fallback):
                candidates.append(fallback)

        if candidates:
            # Stable pick: shortest path first (usually vendor/noVNC), then alphabetic.
            candidates.sort(key=lambda p: (len(str(p)), str(p).lower()))
            novnc_root = candidates[0]
            print(f"[wall] noVNC autodetected: {novnc_root}")
        else:
            raise RuntimeError(
                f"noVNC folder not found or incomplete: {novnc_root}\n"
                "Expected file: vnc_lite.html\n"
                "Extract noVNC into one of these folders:\n"
                "  - vnc_wall/vendor/noVNC\n"
                "  - vnc_wall/vendor/<any-folder-containing-vnc_lite.html>"
            )

    cmd = [
        sys.executable,
        "-m",
        "websockify",
        "--web",
        str(novnc_root),
        f"{config['listen_host']}:{config['websockify_port']}",
        "--token-plugin",
        "TokenFile",
        "--token-source",
        str(tokens_file),
    ]
    return subprocess.Popen(cmd, cwd=str(BASE_DIR))


def ensure_websockify_available() -> None:
    try:
        __import__("websockify")
    except Exception as exc:
        raise RuntimeError(
            "Python module 'websockify' not found.\n"
            "Install it in your environment: py -3 -m pip install websockify"
        ) from exc


def main() -> int:
    config = load_config()
    _validate_auth_config(config)
    rows = load_host_rows(config)
    enabled_hosts = build_enabled_hosts(rows)

    ensure_websockify_available()
    write_tokens(enabled_hosts)
    state_lock = threading.RLock()
    state: dict[str, Any] = {
        "rows": rows,
        "enabled_hosts": enabled_hosts,
        "updated_at": int(time.time()),
    }

    ws_proc: subprocess.Popen | None = None
    server: ThreadingHTTPServer | None = None
    try:
        ws_proc = start_websockify(config, TOKENS_PATH)
        handler = make_handler(config, state, state_lock)
        server = ThreadingHTTPServer((str(config["listen_host"]), int(config["wall_port"])), handler)

        host = str(config["listen_host"])
        if host == "0.0.0.0":
            host = "127.0.0.1"
        print(f"[wall] Dashboard: http://{host}:{config['wall_port']}")
        print(f"[wall] Clients editor: http://{host}:{config['wall_port']}/clients")
        print(f"[wall] noVNC/websockify: http://{host}:{config['websockify_port']}")
        print(f"[wall] Hosts configured: {len(rows)}")
        print(f"[wall] Hosts enabled: {len(enabled_hosts)}")
        if not enabled_hosts:
            print("[wall] No enabled hosts yet. Configure clients from /clients.")
        if config.get("auth_enabled"):
            print("[wall] Dashboard auth: enabled")
            if config.get("_auth_secret_ephemeral"):
                print("[wall] Auth session secret autogenerated for this run (sessions reset on restart).")
        else:
            print("[wall] Dashboard auth: disabled")
        print("[wall] Press Ctrl+C to stop.")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            server.shutdown()
            server.server_close()
        if ws_proc and ws_proc.poll() is None:
            ws_proc.terminate()
            try:
                ws_proc.wait(timeout=5)
            except Exception:
                ws_proc.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
