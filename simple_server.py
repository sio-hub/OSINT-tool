#!/usr/bin/env python3
"""
Simple HTTP server for OSINT Tool web interface
Serves static files and handles API endpoints
"""

import json
import os
import sys
import asyncio
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import httpx
import whois
from dns import resolver, reversename, rdatatype

# Define version for User-Agent
__version__ = "1.0.0"

# Default sites for username checking (reduced list for better reliability)
DEFAULT_SITES = {
    "github": "https://github.com/{username}",
    "twitter": "https://twitter.com/{username}",
    "instagram": "https://instagram.com/{username}",
    "facebook": "https://facebook.com/{username}",
    "linkedin": "https://linkedin.com/in/{username}",
    "youtube": "https://youtube.com/@{username}",
    "reddit": "https://reddit.com/user/{username}",
    "twitch": "https://twitch.tv/{username}",
    "medium": "https://medium.com/@{username}",
    "dev": "https://dev.to/{username}",
    "stackoverflow": "https://stackoverflow.com/users/{username}",
    "behance": "https://behance.net/{username}",
    "dribbble": "https://dribbble.com/{username}",
}

def _safe_run(coro):
    """Safely run async functions"""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # In case already in an event loop, create a new loop
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

def _domain_whois(domain: str):
    """Get WHOIS information for a domain"""
    data = {}
    try:
        w = whois.whois(domain)
        data = {k: v for k, v in w.__dict__.items() if not k.startswith("_") and v}
    except Exception as exc:
        data = {"error": str(exc)}
    return data

def _domain_dns(domain: str):
    """Get DNS records for a domain"""
    out = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=6.0)
            values = []
            for rdata in answers:
                if rtype == "MX":
                    values.append(str(rdata.exchange).rstrip(".") + f" (pref {rdata.preference})")
                else:
                    values.append(str(rdata).strip())
            if values:
                out[rtype] = values
        except Exception:
            continue
    return out

async def _fetch_crtsh(domain: str):
    """Fetch subdomains from crt.sh"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
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
    return sorted(list(subdomains))

def _ip_reverse_ptr(ip: str):
    """Get reverse DNS for an IP"""
    try:
        addr = reversename.from_address(ip)
        answers = resolver.resolve(addr, rdatatype.PTR, lifetime=6.0)
        return str(answers[0]).rstrip(".")
    except Exception:
        return None

async def _ip_info(ip: str):
    """Get IP information from multiple sources"""
    result = {}
    headers = {"User-Agent": f"osint-tool/{__version__}"}
    timeout = httpx.Timeout(10.0)
    
    async with httpx.AsyncClient(headers=headers, timeout=timeout, follow_redirects=True) as client:
        # Try ipinfo.io
        try:
            resp = await client.get(f"https://ipinfo.io/{ip}/json")
            if resp.status_code == 200:
                result["ipinfo"] = resp.json()
        except Exception:
            pass
        
        # Try ip-api.com
        try:
            resp = await client.get(f"http://ip-api.com/json/{ip}")
            if resp.status_code == 200:
                result["ipapi"] = resp.json()
        except Exception:
            pass
    
    return result

async def _check_one_site(client, site: str, url_template: str, username: str):
    """Check if a username exists on a specific site"""
    url = url_template.format(username=username)
    try:
        # Use GET instead of HEAD for better compatibility
        resp = await client.get(url, allow_redirects=True)
        if resp.status_code == 200:
            return site, "exists", url
        elif resp.status_code == 404:
            return site, "not found", url
        else:
            return site, "maybe", url
    except httpx.TimeoutException:
        return site, "timeout", url
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return site, "not found", url
        else:
            return site, "maybe", url
    except Exception:
        return site, "error", url

async def _check_usernames(username: str, sites):
    """Check username across multiple sites"""
    # Use a more realistic User-Agent
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    
    # Longer timeout and more realistic settings
    timeout = httpx.Timeout(10.0, connect=5.0)
    
    async with httpx.AsyncClient(
        headers=headers, 
        timeout=timeout, 
        follow_redirects=True,
        http2=False  # Disable HTTP/2 for better compatibility
    ) as client:
        # Process sites sequentially to avoid rate limiting
        results = []
        for site, url_template in sites.items():
            try:
                result = await _check_one_site(client, site, url_template, username)
                results.append(result)
                # Small delay between requests to avoid rate limiting
                await asyncio.sleep(0.5)
            except Exception as e:
                results.append((site, "error", url_template.format(username=username)))
        
        return results

async def _github_user_data(user: str):
    """Get GitHub user data"""
    headers = {"User-Agent": f"osint-tool/{__version__}"}
    timeout = httpx.Timeout(10.0)
    async with httpx.AsyncClient(headers=headers, timeout=timeout, follow_redirects=True) as client:
        try:
            resp = await client.get(f"https://api.github.com/users/{user}")
            if resp.status_code == 200:
                return resp.json()
            else:
                return {"error": f"User not found or API error: {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

class OSINTHTTPRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Set the directory to serve static files from
        os.chdir(str(Path(__file__).parent / "osint_tool" / "web_static"))
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        """Handle API POST requests"""
        print(f"POST request to: {self.path}")  # Debug
        if self.path.startswith('/api/'):
            self.handle_api_request()
        else:
            self.send_error(404, "API endpoint not found")
    
    def handle_api_request(self):
        """Handle API requests"""
        try:
            # Read the request body
            content_length = int(self.headers.get('Content-Length', 0))
            print(f"Content length: {content_length}")  # Debug
            if content_length > 0:
                body = self.rfile.read(content_length)
                data = json.loads(body.decode('utf-8'))
            else:
                data = {}
            
            # Route to appropriate handler
            if self.path == '/api/domain':
                response = self.handle_domain(data)
            elif self.path == '/api/ip':
                response = self.handle_ip(data)
            elif self.path == '/api/username':
                response = self.handle_username(data)
            elif self.path == '/api/email':
                response = self.handle_email(data)
            elif self.path == '/api/github':
                response = self.handle_github(data)
            elif self.path == '/api/subdomains':
                response = self.handle_subdomains(data)
            else:
                self.send_error(404, "API endpoint not found")
                return
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            print(f"Error in handle_api_request: {e}")  # Debug
            self.send_error(500, f"Server error: {str(e)}")
    
    def handle_domain(self, data):
        """Handle domain API requests"""
        domain = data.get('domain', '').strip()
        do_whois = data.get('whois', True)
        do_dns = data.get('dns', True)
        do_subs = data.get('subdomains', False)
        
        result = {"domain": domain}
        
        if do_whois:
            result["whois"] = _domain_whois(domain)
        
        if do_dns:
            result["dns"] = _domain_dns(domain)
        
        if do_subs:
            result["subdomains"] = _safe_run(_fetch_crtsh(domain))
        
        return result
    
    def handle_ip(self, data):
        """Handle IP API requests"""
        ip = data.get('ip', '').strip()
        details = data.get('details', True)
        reverse = data.get('reverse', True)
        
        result = {"ip": ip}
        
        if reverse:
            result["ptr"] = _ip_reverse_ptr(ip)
        
        if details:
            result["details"] = _safe_run(_ip_info(ip))
        
        return result
    
    def handle_username(self, data):
        """Handle username API requests"""
        username = data.get('username', '').strip()
        sites = data.get('sites')
        
        selected = DEFAULT_SITES
        if isinstance(sites, list) and sites:
            selected = {k: DEFAULT_SITES[k] for k in sites if k in DEFAULT_SITES}
            if not selected:
                selected = DEFAULT_SITES
        
        results = _safe_run(_check_usernames(username, selected))
        data_results = [{"site": s, "status": st, "url": u} for (s, st, u) in results]
        
        return {"username": username, "results": data_results}
    
    def handle_email(self, data):
        """Handle email API requests"""
        address = data.get('address', '').strip()
        print(f"Email check for: {address}")  # Debug
        
        # Basic email validation
        email_re = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
        is_valid = bool(email_re.match(address))
        
        # Extract domain for additional checks
        domain = address.split('@')[-1] if '@' in address else ''
        
        # Gravatar check
        import hashlib
        md5 = hashlib.md5(address.strip().lower().encode("utf-8")).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{md5}?d=404&s=64"
        
        # Check if gravatar exists
        gravatar_exists = False
        try:
            import httpx
            r = httpx.get(gravatar_url, timeout=6.0)
            gravatar_exists = r.status_code == 200
        except Exception:
            pass
        
        # Social media checking (extract username from email and check sites)
        username = address.split('@')[0] if '@' in address else ''
        social_results = []
        
        if username and is_valid:
            try:
                print(f"Checking social media for username: {username}")  # Debug
                # Use the same DEFAULT_SITES for consistency
                social_results = _safe_run(_check_usernames(username, DEFAULT_SITES))
                print(f"Social results: {social_results}")  # Debug
                social_results = [{"site": s, "status": st, "url": u} for (s, st, u) in social_results]
            except Exception as e:
                print(f"Error in email social check: {e}")
                import traceback
                traceback.print_exc()
                social_results = []
        
        result = {
            "address": address,
            "valid_syntax": is_valid,
            "domain": domain,
            "gravatar": {
                "exists": gravatar_exists,
                "url": gravatar_url if gravatar_exists else None
            },
            "social_results": social_results
        }
        
        return result
    
    def handle_github(self, data):
        """Handle GitHub API requests"""
        user = data.get('user', '').strip()
        result = _safe_run(_github_user_data(user))
        return result
    
    def handle_subdomains(self, data):
        """Handle subdomains API requests"""
        domain = data.get('domain', '').strip()
        limit = data.get('limit', 200)
        
        subdomains = _safe_run(_fetch_crtsh(domain))
        if len(subdomains) > limit:
            subdomains = subdomains[:limit]
        
        return {"domain": domain, "subdomains": subdomains, "count": len(subdomains)}
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

def run_server(port=8000):
    """Run the HTTP server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, OSINTHTTPRequestHandler)
    print(f"OSINT Tool server running on http://localhost:{port}")
    print("Press Ctrl+C to stop the server")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.shutdown()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='OSINT Tool Simple HTTP Server')
    parser.add_argument('--port', type=int, default=8000, help='Port to run server on (default: 8000)')
    args = parser.parse_args()
    
    run_server(args.port)
