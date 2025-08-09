from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .cli import (
    _safe_run,
    _domain_whois,
    _domain_dns,
    _fetch_crtsh,
    _ip_reverse_ptr,
    _ip_info,
    _check_usernames,
    DEFAULT_SITES,
    _github_user_data,
)


ROOT_DIR = Path(__file__).resolve().parent
STATIC_DIR = ROOT_DIR / "web_static"

app = FastAPI(title="OSINT Tool Web", version=__version__)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=500, detail="Frontend missing. Reinstall or rebuild.")
    return FileResponse(index_file)


@app.post("/api/domain")
def api_domain(payload: Dict[str, object]) -> JSONResponse:
    domain = str(payload.get("domain", "")).strip()
    do_whois = bool(payload.get("whois", True))
    do_dns = bool(payload.get("dns", True))
    do_subs = bool(payload.get("subdomains", False))
    if not domain:
        raise HTTPException(status_code=400, detail="'domain' is required")
    result: Dict[str, object] = {"domain": domain}
    if do_whois:
        result["whois"] = _domain_whois(domain)
    if do_dns:
        result["dns"] = _domain_dns(domain)
    if do_subs:
        result["subdomains"] = _safe_run(_fetch_crtsh(domain))
    return JSONResponse(result)


@app.post("/api/ip")
def api_ip(payload: Dict[str, object]) -> JSONResponse:
    ip = str(payload.get("ip", "")).strip()
    details = bool(payload.get("details", True))
    reverse = bool(payload.get("reverse", True))
    if not ip:
        raise HTTPException(status_code=400, detail="'ip' is required")
    result: Dict[str, object] = {"ip": ip}
    if reverse:
        result["ptr"] = _ip_reverse_ptr(ip)
    if details:
        result["details"] = _safe_run(_ip_info(ip))
    return JSONResponse(result)


@app.post("/api/username")
def api_username(payload: Dict[str, object]) -> JSONResponse:
    username = str(payload.get("username", "")).strip()
    sites = payload.get("sites")
    if not username:
        raise HTTPException(status_code=400, detail="'username' is required")
    selected = DEFAULT_SITES
    if isinstance(sites, list) and sites:
        selected = {k: DEFAULT_SITES[k] for k in sites if k in DEFAULT_SITES}
        if not selected:
            selected = DEFAULT_SITES
    results = _safe_run(_check_usernames(username, selected))
    # Convert tuples to dict for JSON clarity
    data = [{"site": s, "status": st, "url": u} for (s, st, u) in results]
    return JSONResponse({"username": username, "results": data})


@app.post("/api/email")
def api_email(payload: Dict[str, object]) -> JSONResponse:
    address = str(payload.get("address", "")).strip()
    if not address:
        raise HTTPException(status_code=400, detail="'address' is required")
    email_re = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    is_valid = bool(email_re.match(address))
    md5 = hashlib.md5(address.lower().encode("utf-8")).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{md5}?d=404&s=64"
    import httpx

    exists = False
    try:
        r = httpx.get(gravatar_url, timeout=6.0)
        exists = r.status_code == 200
    except Exception:
        exists = False
    return JSONResponse({
        "address": address,
        "valid_syntax": is_valid,
        "gravatar": {"exists": exists, "url": gravatar_url if exists else None},
    })


@app.post("/api/github")
def api_github(payload: Dict[str, object]) -> JSONResponse:
    user = str(payload.get("user", "")).strip()
    if not user:
        raise HTTPException(status_code=400, detail="'user' is required")
    data = _safe_run(_github_user_data(user))
    return JSONResponse({"user": user, **data})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("osint_tool.webapp:app", host="127.0.0.1", port=8000, reload=True)


