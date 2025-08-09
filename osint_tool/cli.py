from __future__ import annotations

import asyncio
import os
import re
from typing import Dict, List, Optional, Tuple, Iterable

import httpx
import typer
import whois
from dns import resolver, reversename, rdatatype
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from . import __version__

load_dotenv(override=False)

app = typer.Typer(add_completion=False, no_args_is_help=True, help="OSINT CLI for domains, IPs, usernames, emails, and GitHub users")
console = Console()


# ----------------------
# Utilities
# ----------------------

def _safe_run(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # In case already in an event loop (rare on Windows CLI), create a new loop
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def _format_value(value: object) -> str:
    if isinstance(value, (list, tuple, set)):
        try:
            return ", ".join(str(v) for v in value)
        except Exception:
            return str(list(value))
    return str(value)


def _print_kv(title: str, data: Dict[str, object]) -> None:
    table = Table(title=title, show_header=True, header_style="bold magenta", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    for key, value in data.items():
        table.add_row(str(key), _format_value(value))
    console.print(table)


# ----------------------
# Domain intel
# ----------------------

def _domain_whois(domain: str) -> Dict[str, object]:
    data: Dict[str, object] = {}
    try:
        w = whois.whois(domain)
        data = {k: v for k, v in w.__dict__.items() if not k.startswith("_") and v}
    except Exception as exc:  # whois can be flaky depending on TLDs
        data = {"error": str(exc)}
    return data


def _domain_dns(domain: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=6.0)
            values: List[str] = []
            for rdata in answers:
                if rtype == "MX":
                    values.append(str(rdata.exchange).rstrip(".") + f" (pref {rdata.preference})")
                else:
                    values.append(str(rdata).strip())
            if values:
                out[rtype] = values
        except Exception:
            # missing or unsupported record type is fine
            continue
    return out


async def _fetch_crtsh(domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains: set[str] = set()
    headers = {"User-Agent": f"osint-tool/{__version__}"}
    timeout = httpx.Timeout(10.0)
    async with httpx.AsyncClient(headers=headers, timeout=timeout, follow_redirects=True) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                try:
                    items = resp.json()
                except Exception:
                    items = []
                for item in items or []:
                    name_value = item.get("name_value")
                    if not name_value:
                        continue
                    for line in str(name_value).split("\n"):
                        hostname = line.strip().lower().rstrip(".")
                        if hostname.endswith(domain.lower()):
                            subdomains.add(hostname)
        except Exception:
            pass
    return sorted(subdomains)


@app.command()
def domain(
    domain: str = typer.Argument(..., help="Domain name, e.g., example.com"),
    whois_: bool = typer.Option(True, "--whois/--no-whois", help="Include WHOIS output"),
    whois_summary: bool = typer.Option(True, "--whois-summary/--no-whois-summary", help="Show summarized WHOIS fields"),
    dns: bool = typer.Option(True, "--dns/--no-dns", help="Include DNS records"),
    subdomains: bool = typer.Option(False, "--subdomains/--no-subdomains", help="Discover subdomains via crt.sh"),
) -> None:
    """Gather domain intelligence."""
    console.rule(f"Domain intel for [bold]{domain}[/bold]")
    if whois_:
        data = _domain_whois(domain)
        if data:
            if whois_summary:
                summary_keys = [
                    "domain_name",
                    "registrar",
                    "status",
                    "name_servers",
                    "emails",
                    "creation_date",
                    "updated_date",
                    "expiration_date",
                ]
                summary = {k: v for k, v in data.items() if k in summary_keys}
                if summary:
                    _print_kv("WHOIS (summary)", summary)
            else:
                _print_kv("WHOIS (full)", data)
    if dns:
        data = _domain_dns(domain)
        if data:
            for rtype, values in data.items():
                table = Table(title=f"DNS {rtype}", show_header=False, box=box.SIMPLE)
                for v in values:
                    table.add_row(v)
                console.print(table)
    if subdomains:
        subs = _safe_run(_fetch_crtsh(domain))
        if subs:
            table = Table(title="Subdomains (crt.sh)", show_header=False, box=box.SIMPLE)
            for s in subs:
                table.add_row(s)
            console.print(table)


# ----------------------
# IP intel
# ----------------------

def _ip_reverse_ptr(ip: str) -> Optional[str]:
    try:
        addr = reversename.from_address(ip)
        answers = resolver.resolve(addr, rdatatype.PTR, lifetime=6.0)
        for r in answers:
            return str(r).rstrip(".")
    except Exception:
        return None
    return None


async def _ip_info(ip: str) -> Dict[str, object]:
    headers = {"User-Agent": f"osint-tool/{__version__}"}
    timeout = httpx.Timeout(10.0)
    out: Dict[str, object] = {}
    token = os.getenv("IPINFO_TOKEN")
    async with httpx.AsyncClient(headers=headers, timeout=timeout, follow_redirects=True) as client:
        # ipinfo.io
        url_ipinfo = f"https://ipinfo.io/{ip}/json"
        params = {"token": token} if token else None
        try:
            r1 = await client.get(url_ipinfo, params=params)
            if r1.status_code == 200:
                out["ipinfo"] = r1.json()
        except Exception:
            pass
        # ip-api.com
        url_ipapi = f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,asname,reverse,proxy,hosting,query"
        try:
            r2 = await client.get(url_ipapi)
            if r2.status_code == 200:
                out["ipapi"] = r2.json()
        except Exception:
            pass
    return out


@app.command()
def ip(
    ip: str = typer.Argument(..., help="IPv4 or IPv6 address"),
    details: bool = typer.Option(True, "--details/--no-details", help="Query public IP datasets"),
    reverse: bool = typer.Option(True, "--reverse/--no-reverse", help="Resolve PTR (reverse DNS)"),
) -> None:
    """Gather IP intelligence."""
    console.rule(f"IP intel for [bold]{ip}[/bold]")
    if reverse:
        ptr = _ip_reverse_ptr(ip)
        _print_kv("Reverse DNS", {"PTR": ptr or "(none)"})
    if details:
        data = _safe_run(_ip_info(ip))
        for source, payload in data.items():
            _print_kv(f"{source}", payload if isinstance(payload, dict) else {"data": payload})


# ----------------------
# Username presence
# ----------------------

DEFAULT_SITES: Dict[str, str] = {
    "github": "https://github.com/{username}",
    "gitlab": "https://gitlab.com/{username}",
    "twitter": "https://x.com/{username}",
    "reddit": "https://www.reddit.com/user/{username}",
    "instagram": "https://www.instagram.com/{username}",
    "facebook": "https://www.facebook.com/{username}",
    "threads": "https://www.threads.net/@{username}",
    "linkedin_in": "https://www.linkedin.com/in/{username}",
    "linkedin_company": "https://www.linkedin.com/company/{username}",
    "tiktok": "https://www.tiktok.com/@{username}",
    "pinterest": "https://www.pinterest.com/{username}",
    "medium": "https://medium.com/@{username}",
    "devto": "https://dev.to/{username}",
    "stackoverflow": "https://stackoverflow.com/users/{username}",
    "telegram": "https://t.me/{username}",
    # Additional popular platforms
    "youtube": "https://www.youtube.com/@{username}",
    "twitch": "https://www.twitch.tv/{username}",
    "soundcloud": "https://soundcloud.com/{username}",
    "bitbucket": "https://bitbucket.org/{username}",
    "npm": "https://www.npmjs.com/~{username}",
    "pypi": "https://pypi.org/user/{username}",
    "kaggle": "https://www.kaggle.com/{username}",
    "hackerrank": "https://www.hackerrank.com/{username}",
    "leetcode": "https://leetcode.com/{username}",
    "keybase": "https://keybase.io/{username}",
    "behance": "https://www.behance.net/{username}",
    "dribbble": "https://dribbble.com/{username}",
    "flickr": "https://www.flickr.com/people/{username}",
    "producthunt": "https://www.producthunt.com/@{username}",
    "angel": "https://angel.co/u/{username}",
    "tryhackme": "https://tryhackme.com/p/{username}",
    "hackerone": "https://hackerone.com/{username}",
}


async def _check_one_site(client: httpx.AsyncClient, site: str, url_template: str, username: str) -> Tuple[str, str, str]:
    url = url_template.format(username=username)
    try:
        r = await client.get(url, timeout=10.0)
        status = r.status_code
        if status == 200:
            return (site, "exists", url)
        if status in (301, 302, 303, 307, 308) and r.url:
            # Redirects may still indicate presence
            return (site, "maybe", str(r.url))
        if status == 404:
            return (site, "not found", url)
        if status == 429:
            return (site, "rate limited", url)
        return (site, f"unknown ({status})", url)
    except httpx.TimeoutException:
        return (site, "timeout", url)
    except Exception as exc:
        return (site, f"error: {type(exc).__name__}", url)


async def _check_usernames(username: str, sites: Dict[str, str]) -> List[Tuple[str, str, str]]:
    headers = {"User-Agent": f"osint-tool/{__version__}"}
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    timeout = httpx.Timeout(10.0)
    async with httpx.AsyncClient(headers=headers, limits=limits, timeout=timeout, follow_redirects=True) as client:
        tasks = [_check_one_site(client, site, url, username) for site, url in sites.items()]
        return await asyncio.gather(*tasks)


@app.command()
def username(
    username: str = typer.Argument(..., help="Username/handle to search for"),
    sites: Optional[str] = typer.Option(None, help="Comma-separated site keys to check; default checks common sites"),
) -> None:
    """Check username presence across common platforms (best-effort)."""
    selected: Dict[str, str]
    if sites:
        keys = [s.strip().lower() for s in sites.split(",") if s.strip()]
        selected = {k: DEFAULT_SITES[k] for k in keys if k in DEFAULT_SITES}
        if not selected:
            console.print("[yellow]No matching sites from input; using defaults[/yellow]")
            selected = DEFAULT_SITES
    else:
        selected = DEFAULT_SITES

    console.rule(f"Username checks for [bold]{username}[/bold]")
    results = _safe_run(_check_usernames(username, selected))
    table = Table(show_header=True, header_style="bold magenta", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Site", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("URL", style="green")
    for site, status, url in sorted(results, key=lambda t: t[0]):
        table.add_row(site, status, url)
    console.print(table)


# ----------------------
# Email quick checks
# ----------------------

@app.command()
def email(
    address: str = typer.Argument(..., help="Email address to inspect"),
) -> None:
    """Basic email validation and Gravatar existence check."""
    console.rule(f"Email checks for [bold]{address}[/bold]")
    # Simple RFC 5322-inspired regex (not perfect but practical)
    email_re = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    is_valid = bool(email_re.match(address))
    _print_kv("Validation", {"valid_syntax": is_valid})

    import hashlib

    md5 = hashlib.md5(address.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/avatar/{md5}?d=404&s=64"
    try:
        r = httpx.get(url, timeout=6.0)
        exists = r.status_code == 200
    except Exception:
        exists = False
    _print_kv("Gravatar", {"exists": exists, "url": url if exists else "(no gravatar)"})


# ----------------------
# GitHub user
# ----------------------

async def _github_user_data(user: str) -> Dict[str, object]:
    headers = {"User-Agent": f"osint-tool/{__version__}"}
    timeout = httpx.Timeout(10.0)
    out: Dict[str, object] = {}
    async with httpx.AsyncClient(headers=headers, timeout=timeout, follow_redirects=True) as client:
        try:
            u = await client.get(f"https://api.github.com/users/{user}")
            if u.status_code == 200:
                out["user"] = u.json()
            r = await client.get(f"https://api.github.com/users/{user}/repos", params={"per_page": 100, "sort": "updated"})
            if r.status_code == 200:
                # Only keep small subset of fields for readability
                repos = [
                    {"name": repo.get("name"), "visibility": repo.get("visibility"), "fork": repo.get("fork"), "updated_at": repo.get("updated_at"), "language": repo.get("language"), "stargazers_count": repo.get("stargazers_count")}
                    for repo in r.json() or []
                ]
                out["repos"] = repos
        except Exception:
            pass
    return out


@app.command()
def github(
    user: str = typer.Argument(..., help="GitHub username"),
) -> None:
    """Fetch GitHub user profile and repos (unauthenticated)."""
    console.rule(f"GitHub for [bold]{user}[/bold]")
    data = _safe_run(_github_user_data(user))
    if "user" in data:
        _print_kv("Profile", data["user"])  # type: ignore[arg-type]
    if "repos" in data:
        table = Table(title="Repositories", show_header=True, header_style="bold magenta", box=box.MINIMAL)
        table.add_column("name")
        table.add_column("lang")
        table.add_column("stars")
        table.add_column("updated")
        for repo in data["repos"]:  # type: ignore[index]
            table.add_row(
                str(repo.get("name")),
                str(repo.get("language")),
                str(repo.get("stargazers_count")),
                str(repo.get("updated_at")),
            )
        console.print(table)


# ----------------------
# Version
# ----------------------

@app.command()
def version() -> None:
    """Show tool version."""
    console.print(Panel.fit(f"osint-tool v{__version__}", border_style="green"))


