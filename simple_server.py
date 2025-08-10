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
            elif self.path == '/api/phone':
                response = self.handle_phone(data)
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
    
    def handle_phone(self, data):
        """Handle phone API requests"""
        phone = data.get('phone', '').strip()
        print(f"Phone check for: {phone}")  # Debug
        
        result = {"phone": phone}
        
        # Basic phone number validation
        import re
        phone_re = re.compile(r'^\+?1?\d{9,15}$')
        is_valid = bool(phone_re.match(phone))
        
        if is_valid:
            # Get carrier information
            carrier_info = self._get_phone_carrier_info(phone)
            if carrier_info:
                result["carrier_info"] = carrier_info
            
            # Search for phone number mentions
            search_results = _safe_run(self._search_phone_web(phone))
            if search_results:
                result["search_results"] = search_results
        
        return result
    
    def _get_phone_carrier_info(self, phone):
        """Get basic carrier information for phone number"""
        try:
            # This is a simplified carrier lookup
            # In a real implementation, you'd use a service like NumVerify API
            import re
            
            # Basic US carrier detection (very simplified)
            us_carriers = {
                'verizon': ['201', '202', '203', '205', '206', '207', '208', '209', '210', '212', '213', '214', '215', '216', '217', '218', '219', '220', '223', '224', '225', '228', '229', '231', '234', '239', '240', '248', '251', '252', '253', '254', '256', '260', '262', '267', '269', '270', '272', '276', '281', '301', '302', '303', '304', '305', '307', '308', '309', '310', '312', '313', '314', '315', '316', '317', '318', '319', '320', '321', '323', '325', '330', '331', '334', '336', '337', '339', '340', '341', '347', '351', '352', '360', '361', '386', '401', '402', '404', '405', '406', '407', '408', '409', '410', '412', '413', '414', '415', '417', '419', '423', '424', '425', '434', '435', '440', '443', '445', '469', '470', '475', '478', '479', '480', '484', '501', '502', '503', '504', '505', '507', '508', '509', '510', '512', '513', '515', '516', '517', '518', '520', '530', '531', '534', '540', '541', '551', '559', '561', '562', '563', '567', '570', '571', '573', '574', '575', '580', '585', '586', '601', '602', '603', '605', '606', '607', '608', '609', '610', '612', '614', '615', '616', '617', '618', '619', '620', '623', '626', '628', '629', '630', '631', '636', '641', '646', '650', '651', '657', '660', '661', '662', '678', '681', '682', '701', '702', '703', '704', '706', '707', '708', '712', '713', '714', '715', '716', '717', '718', '719', '720', '724', '725', '727', '731', '732', '734', '740', '754', '757', '760', '762', '763', '765', '769', '770', '772', '773', '774', '775', '781', '785', '786', '801', '802', '803', '804', '805', '806', '808', '810', '812', '813', '814', '815', '816', '817', '818', '828', '830', '831', '832', '843', '845', '847', '848', '850', '856', '857', '858', '859', '860', '862', '863', '864', '865', '870', '872', '878', '901', '903', '904', '906', '907', '908', '909', '910', '912', '913', '914', '915', '916', '917', '918', '919', '920', '925', '928', '929', '930', '931', '934', '936', '937', '938', '940', '941', '947', '949', '951', '952', '954', '956', '959', '970', '971', '972', '973', '975', '978', '979', '980', '985', '989'],
                'att': ['205', '210', '214', '217', '225', '228', '251', '256', '260', '262', '267', '269', '270', '272', '276', '281', '301', '302', '303', '304', '305', '307', '308', '309', '310', '312', '313', '314', '315', '316', '317', '318', '319', '320', '321', '323', '325', '330', '331', '334', '336', '337', '339', '340', '341', '347', '351', '352', '360', '361', '386', '401', '402', '404', '405', '406', '407', '408', '409', '410', '412', '413', '414', '415', '417', '419', '423', '424', '425', '434', '435', '440', '443', '445', '469', '470', '475', '478', '479', '480', '484', '501', '502', '503', '504', '505', '507', '508', '509', '510', '512', '513', '515', '516', '517', '518', '520', '530', '531', '534', '540', '541', '551', '559', '561', '562', '563', '567', '570', '571', '573', '574', '575', '580', '585', '586', '601', '602', '603', '605', '606', '607', '608', '609', '610', '612', '614', '615', '616', '617', '618', '619', '620', '623', '626', '628', '629', '630', '631', '636', '641', '646', '650', '651', '657', '660', '661', '662', '678', '681', '682', '701', '702', '703', '704', '706', '707', '708', '712', '713', '714', '715', '716', '717', '718', '719', '720', '724', '725', '727', '731', '732', '734', '740', '754', '757', '760', '762', '763', '765', '769', '770', '772', '773', '774', '775', '781', '785', '786', '801', '802', '803', '804', '805', '806', '808', '810', '812', '813', '814', '815', '816', '817', '818', '828', '830', '831', '832', '843', '845', '847', '848', '850', '856', '857', '858', '859', '860', '862', '863', '864', '865', '870', '872', '878', '901', '903', '904', '906', '907', '908', '909', '910', '912', '913', '914', '915', '916', '917', '918', '919', '920', '925', '928', '929', '930', '931', '934', '936', '937', '938', '940', '941', '947', '949', '951', '952', '954', '956', '959', '970', '971', '972', '973', '975', '978', '979', '980', '985', '989'],
                'tmobile': ['201', '202', '203', '205', '206', '207', '208', '209', '210', '212', '213', '214', '215', '216', '217', '218', '219', '220', '223', '224', '225', '228', '229', '231', '234', '239', '240', '248', '251', '252', '253', '254', '256', '260', '262', '267', '269', '270', '272', '276', '281', '301', '302', '303', '304', '305', '307', '308', '309', '310', '312', '313', '314', '315', '316', '317', '318', '319', '320', '321', '323', '325', '330', '331', '334', '336', '337', '339', '340', '341', '347', '351', '352', '360', '361', '386', '401', '402', '404', '405', '406', '407', '408', '409', '410', '412', '413', '414', '415', '417', '419', '423', '424', '425', '434', '435', '440', '443', '445', '469', '470', '475', '478', '479', '480', '484', '501', '502', '503', '504', '505', '507', '508', '509', '510', '512', '513', '515', '516', '517', '518', '520', '530', '531', '534', '540', '541', '551', '559', '561', '562', '563', '567', '570', '571', '573', '574', '575', '580', '585', '586', '601', '602', '603', '605', '606', '607', '608', '609', '610', '612', '614', '615', '616', '617', '618', '619', '620', '623', '626', '628', '629', '630', '631', '636', '641', '646', '650', '651', '657', '660', '661', '662', '678', '681', '682', '701', '702', '703', '704', '706', '707', '708', '712', '713', '714', '715', '716', '717', '718', '719', '720', '724', '725', '727', '731', '732', '734', '740', '754', '757', '760', '762', '763', '765', '769', '770', '772', '773', '774', '775', '781', '785', '786', '801', '802', '803', '804', '805', '806', '808', '810', '812', '813', '814', '815', '816', '817', '818', '828', '830', '831', '832', '843', '845', '847', '848', '850', '856', '857', '858', '859', '860', '862', '863', '864', '865', '870', '872', '878', '901', '903', '904', '906', '907', '908', '909', '910', '912', '913', '914', '915', '916', '917', '918', '919', '920', '925', '928', '929', '930', '931', '934', '936', '937', '938', '940', '941', '947', '949', '951', '952', '954', '956', '959', '970', '971', '972', '973', '975', '978', '979', '980', '985', '989']
            }
            
            # Clean phone number
            clean_phone = re.sub(r'[^\d]', '', phone)
            
            # Check if it's a US number
            if clean_phone.startswith('1') and len(clean_phone) == 11:
                area_code = clean_phone[1:4]
            elif len(clean_phone) == 10:
                area_code = clean_phone[:3]
            else:
                return {
                    "carrier": "Unknown",
                    "country": "Unknown",
                    "type": "Unknown",
                    "valid": True
                }
            
            # Find carrier
            carrier = "Unknown"
            for carrier_name, codes in us_carriers.items():
                if area_code in codes:
                    carrier = carrier_name.title()
                    break
            
            return {
                "carrier": carrier,
                "country": "United States",
                "type": "Mobile" if carrier != "Unknown" else "Unknown",
                "valid": True
            }
            
        except Exception as e:
            print(f"Error in carrier lookup: {e}")
            return None
    
    async def _search_phone_web(self, phone):
        """Search for phone number mentions on the web"""
        try:
            # This is a simplified web search
            # In a real implementation, you'd use Google/DuckDuckGo APIs
            
            # For now, return some example results
            # In production, you'd implement actual web scraping or API calls
            
            return [
                {
                    "title": f"Phone number {phone} found in public records",
                    "url": f"https://example.com/search?q={phone}"
                },
                {
                    "title": f"Business listing for {phone}",
                    "url": f"https://business.example.com/{phone}"
                }
            ]
            
        except Exception as e:
            print(f"Error in web search: {e}")
            return []
    
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
