from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

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
load_dotenv(override=False)


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
    
    # Also check for social media accounts using the email
    username = address.split('@')[0] if '@' in address else address
    social_results = _safe_run(_check_usernames(username, DEFAULT_SITES))
    social_data = [{"site": s, "status": st, "url": u} for (s, st, u) in social_results]
    
    return JSONResponse({
        "address": address,
        "valid_syntax": is_valid,
        "gravatar": {"exists": exists, "url": gravatar_url if exists else None},
        "social_results": social_data,
    })


@app.post("/api/github")
def api_github(payload: Dict[str, object]) -> JSONResponse:
    user = str(payload.get("user", "")).strip()
    if not user:
        raise HTTPException(status_code=400, detail="'user' is required")
    data = _safe_run(_github_user_data(user))
    return JSONResponse({"user": user, **data})

class SubdomainsPayload(BaseModel):
    domain: str
    resolve: bool = False
    limit: int = 200


@app.post("/api/subdomains")
def api_subdomains(payload: SubdomainsPayload) -> JSONResponse:
    domain = payload.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="'domain' is required")
    try:
        subs = _safe_run(_fetch_crtsh(domain))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Subdomain source error: {type(exc).__name__}")
    limit = max(0, int(payload.limit or 0))
    if limit:
        subs = subs[:limit]
    if not payload.resolve:
        return JSONResponse({"domain": domain, "count": len(subs), "subdomains": subs})
    # Resolve A records for each subdomain (best-effort, short timeout)
    from dns import resolver
    results: List[Dict[str, object]] = []
    for host in subs:
        ips: List[str] = []
        try:
            answers = resolver.resolve(host, "A", lifetime=3.0)
            for r in answers:
                ips.append(str(r))
        except Exception:
            pass
        results.append({"host": host, "ips": ips})
    return JSONResponse({"domain": domain, "count": len(results), "results": results})


# ----------------------
# AI endpoints (OpenAI)
# ----------------------

class AISummarizePayload(BaseModel):
    target: str
    kind: str  # domain|ip|username|email|github
    max_tokens: int | None = 400
    api_key: Optional[str] = None


class AIAskPayload(BaseModel):
    question: str
    context: Dict[str, object] | None = None
    max_tokens: int | None = 400
    api_key: Optional[str] = None


def _openai_client(override_key: Optional[str] = None):
    import os
    from openai import OpenAI

    key = override_key or os.getenv("OPENAI_API_KEY")
    if not key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not set. Set it in your env or .env, then restart the server.")
    return OpenAI(api_key=key)


def _gather_context(kind: str, target: str) -> Dict[str, object]:
    kind = (kind or "").lower().strip()
    if kind == "domain":
        return {
            "domain": target,
            "whois": _domain_whois(target),
            "dns": _domain_dns(target),
            "subdomains": _safe_run(_fetch_crtsh(target))[:100],
        }
    if kind == "ip":
        return {
            "ip": target,
            "ptr": _ip_reverse_ptr(target),
            "details": _safe_run(_ip_info(target)),
        }
    if kind == "username":
        results = _safe_run(_check_usernames(target, DEFAULT_SITES))
        return {"username": target, "results": results}
    if kind == "email":
        # reuse email logic minimalistically
        import hashlib, httpx, re
        email_re = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
        is_valid = bool(email_re.match(target))
        md5 = hashlib.md5(target.lower().encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/avatar/{md5}?d=404&s=64"
        exists = False
        try:
            r = httpx.get(url, timeout=6.0)
            exists = r.status_code == 200
        except Exception:
            pass
        return {"address": target, "valid_syntax": is_valid, "gravatar": {"exists": exists}}
    if kind == "github":
        return {"user": target, **_safe_run(_github_user_data(target))}
    raise HTTPException(status_code=400, detail="Unsupported kind")


def _summarize_with_openai(context: Dict[str, object], max_tokens: int | None = 400, api_key: Optional[str] = None) -> str:
    try:
        client = _openai_client(api_key)
        system = (
            "You are an OSINT analyst. Summarize key findings from the JSON context, "
            "highlighting risks, infrastructure, presence, and anomalies. Provide concise bullets and 3 recommended next actions."
        )
        user = (
            "Context (JSON):\n" + str(context) + "\n\n"
            "Output in markdown with headings: Findings, Recommendations. Keep it tight."
        )
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            max_tokens=max_tokens or 400,
            temperature=0.2,
        )
        return res.choices[0].message.content or ""
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OpenAI error: {type(exc).__name__}")


@app.post("/api/ai/summarize")
def api_ai_summarize(payload: AISummarizePayload) -> JSONResponse:
    context = _gather_context(payload.kind, payload.target)
    summary = _summarize_with_openai(context, payload.max_tokens, payload.api_key)
    return JSONResponse({"target": payload.target, "kind": payload.kind, "summary_md": summary, "context": context})


@app.post("/api/ai/ask")
def api_ai_ask(payload: AIAskPayload) -> JSONResponse:
    try:
        client = _openai_client(payload.api_key)
        system = "You are a precise OSINT assistant. Answer strictly from the provided context."
        context_str = str(payload.context or {})
        prompt = f"Context (JSON):\n{context_str}\n\nQuestion: {payload.question}\nAnswer concisely in bullet points."
        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            max_tokens=payload.max_tokens or 400,
            temperature=0.2,
        )
        return JSONResponse({"answer_md": res.choices[0].message.content or ""})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OpenAI error: {type(exc).__name__}")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("osint_tool.webapp:app", host="127.0.0.1", port=8000, reload=True)


