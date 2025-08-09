## OSINT-tool

 A sleek Python OSINT toolkit with a no-nonsense CLI and a modern web UI (dark by default, obviously).

### What it does
- **Domain**: WHOIS, DNS records, certificate-transparency subdomains (crt.sh)
- **IP**: IP info (ipinfo.io if token present), geolocation (ip-api), reverse DNS (PTR)
- **Username**: Presence checks across popular platforms (best-effort, no scraping)
- **Email**: Syntax validation, Gravatar lookup
- **GitHub**: User profile + recent repos

### Requirements
- Python 3.9+
- Windows PowerShell recommended (works anywhere Python works)
- Optional: OpenAI API key for AI features (or enter it directly in the web UI)

## Install and run

### Quickstart (copy/paste)
```powershell
cd C:\Users\sion\Documents\GitHub\OSINT-tool
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m uvicorn osint_tool.webapp:app --reload --host 127.0.0.1 --port 8000
# Open http://127.0.0.1:8000
```

### 1) Setup the virtual environment
```powershell
cd C:\Users\sion\Documents\GitHub\OSINT-tool
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Optional: copy and fill tokens if you have them
Copy-Item .env.example .env
# For AI features (OpenAI):
setx OPENAI_API_KEY "YOUR_API_KEY_HERE"
```

If PowerShell complains about scripts:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

### 2) Run the CLI (terminal mode)
```powershell
# Discover commands
python -m osint_tool --help

# Version
python -m osint_tool version

# Domain intel
python -m osint_tool domain example.com --whois --dns --subdomains

# IP intel
python -m osint_tool ip 8.8.8.8 --details --reverse

# Username presence
python -m osint_tool username johndoe

# Email checks
python -m osint_tool email someone@example.com

# GitHub user
python -m osint_tool github torvalds
```

CLI tips:
- WHOIS prints a concise summary by default. Prefer the full dossier? Add `--no-whois-summary`.
- Lists are formatted for human eyes — no brackets soup.

### 3) Run the Web UI (dark and delightful)
```powershell
# Using the venv’s Python
python -m uvicorn osint_tool.webapp:app --reload --host 127.0.0.1 --port 8000
```
Then open `http://127.0.0.1:8000`.

Web tips:
- There’s a **theme toggle** in the navbar. Dark is default (because night ops). Light is there if you must.
- Tabs: Domain, IP, Username, Email, GitHub, Subdomains, AI.
- Domain/IP/Username/Email/GitHub all have clean card/table views.
- Subdomains tab: enter domain, adjust limit, optionally resolve A records, then Run.
- AI tab: either set `OPENAI_API_KEY` in your environment or paste your key in the field, then Summarize or Ask.

### Running without activating the venv
```powershell
C:\Users\sion\Documents\GitHub\OSINT-tool\.venv\Scripts\python -m pip install -r requirements.txt
C:\Users\sion\Documents\GitHub\OSINT-tool\.venv\Scripts\python -m uvicorn osint_tool.webapp:app --reload --host 127.0.0.1 --port 8000
```

### Simple static server (UI only)
If you just want to preview the UI without the API, serve the static files:
```powershell
python -m http.server 8000 -d osint_tool/web_static
```
Open `http://127.0.0.1:8000`. Note: buttons will fail because the API isn’t running. To use the full app, start uvicorn as shown above.

## Optional environment variables
Add these to `.env` if available (they’re optional):
- **IPINFO_TOKEN**: enriches IP lookups via `ipinfo.io`
- **HIBP_API_KEY**: HaveIBeenPwned (paid API)
- **SHODAN_API_KEY**: Shodan (future integrations)
- **OPENAI_API_KEY**: Enables AI summarize/Q&A in the Web UI

## Troubleshooting (keep it stealthy)
- “No module named uvicorn” → You’re using the wrong Python. Activate the venv or run the venv’s Python directly.
  ```powershell
  .\.venv\Scripts\Activate.ps1
  python -m pip install uvicorn==0.30.6
  ```
- “Activation is disabled” → Relax, and run:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
  ```
- pip missing in venv →
  ```powershell
  .\.venv\Scripts\python -m ensurepip --upgrade
  ```
- Port 8000 is busy → change the port:
  ```powershell
  python -m uvicorn osint_tool.webapp:app --reload --port 8001
  ```
- AI errors complaining about credentials → set your key:
  ```powershell
  setx OPENAI_API_KEY "YOUR_API_KEY_HERE"
  # then restart the terminal so the change takes effect
  ```
 - Alternatively, paste your key directly into the AI tab’s “OpenAI API Key” field (sent only for that request).

## Feature guide

### Subdomains enumeration
- UI: Subdomains tab → enter `example.com` → choose limit → toggle “Resolve A records” if needed → Run.
- API: `POST /api/subdomains` with `{ domain: "example.com", limit: 200, resolve: true }`.
- CLI: `python -m osint_tool domain example.com --subdomains` (lists from crt.sh).

### AI summarize and Q&A
- UI: AI tab → enter target + kind (domain/ip/username/email/github).
  - Provide `OPENAI_API_KEY` via environment (recommended) or paste into the API key field.
  - Click Summarize to get Findings + Recommendations; Ask to query the context.
- API:
  - `POST /api/ai/summarize` body: `{ target, kind, api_key? }`
  - `POST /api/ai/ask` body: `{ question, context, api_key? }`
- Notes:
  - Data you enter may be sent to OpenAI if you use cloud AI. Avoid sensitive info or use a local model (we can switch to Ollama on request).

## What’s inside
- `osint_tool/cli.py` — the CLI commands (domain, ip, username, email, github)
- `osint_tool/webapp.py` — FastAPI app serving API + static UI
- `osint_tool/web_static/index.html` — the modern UI with dark blue/black palette and theme toggle
- `requirements.txt` — dependencies
- `.env.example` — optional tokens

## Roadmap (call your shots)
- More data providers (Shodan, VirusTotal, HIBP direct)
- Export to JSON/CSV from the web UI
- Caching and rate-limit awareness
- Docker + one-liner deploy

If you want any of these right now, ask — we’ll gear up and ship.

### Optional environment variables
Create a `.env` file (see `.env.example`).

- IPINFO_TOKEN: token for `ipinfo.io`
- HIBP_API_KEY: HaveIBeenPwned API key (optional, paid)
- SHODAN_API_KEY: Shodan API key (optional)

### Notes
- Be mindful of rate limits and terms of service of third-party services.
- This tool performs lightweight, non-invasive HTTP requests; scraping and login-required data are out of scope.


