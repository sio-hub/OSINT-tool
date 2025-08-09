## OSINT-tool

Python-based OSINT CLI to gather publicly available information about domains, IPs, usernames, emails, and GitHub users. Designed to be modular and API-key optional so you can start quickly and enrich as you go.

### Features
- Domain: WHOIS, DNS records, certificate transparency subdomain discovery (crt.sh)
- IP: IP info (ipinfo.io if token provided), geolocation (ip-api), reverse DNS (PTR)
- Username: Check presence across common platforms via HTTP checks
- Email: Basic validation and Gravatar existence check; optional HaveIBeenPwned if API key provided
- GitHub: User profile and repositories

### Requirements
- Python 3.9+

### Quick start
```bash
python -m venv .venv
. .venv/Scripts/activate  # On Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Optional: copy and fill environment variables
copy .env.example .env  # On PowerShell

# See commands
python -m osint_tool --help

# Start web app (FastAPI)
python -m uvicorn osint_tool.webapp:app --reload
```

### Usage examples
```bash
# Domain intel
python -m osint_tool domain example.com --whois --dns --subdomains

# IP intel
python -m osint_tool ip 8.8.8.8 --details --reverse

# Username presence
python -m osint_tool username johndoe

# Email quick checks
python -m osint_tool email someone@example.com

# GitHub user
python -m osint_tool github torvalds
```

### Web UI
- Start server:
  ```bash
  uvicorn osint_tool.webapp:app --reload
  ```
- Open `http://127.0.0.1:8000` in your browser.

### Optional environment variables
Create a `.env` file (see `.env.example`).

- IPINFO_TOKEN: token for `ipinfo.io`
- HIBP_API_KEY: HaveIBeenPwned API key (optional, paid)
- SHODAN_API_KEY: Shodan API key (optional)

### Notes
- Be mindful of rate limits and terms of service of third-party services.
- This tool performs lightweight, non-invasive HTTP requests; scraping and login-required data are out of scope.


