# OSINT Tool

A comprehensive Python OSINT toolkit with both command-line interface and modern web UI for gathering intelligence on domains, IPs, usernames, emails, and GitHub users.

## 🚀 Features

- **Domain Intelligence**: WHOIS lookup, DNS records, subdomain enumeration
- **IP Analysis**: Geolocation, reverse DNS, ISP details, proxy detection
- **Username Hunting**: Check 13+ social media platforms for username availability
- **Email Validation**: Syntax check, Gravatar lookup, social media presence
- **AI Integration**: OpenAI-powered summarization and Q&A over gathered intel
- **Web Interface**: Modern dark-themed UI with real-time results

## 📋 Prerequisites

Before you begin, ensure you have:

- **Python 3.8 or higher** installed on your system
- **Git** (for cloning the repository)
- **Internet connection** (for API calls and lookups)
- **OpenAI API key** (optional, for AI features)

### Checking Your Python Version

**Windows:**
```bash
python --version
```

**macOS/Linux:**
```bash
python3 --version
```

If Python is not installed, download it from [python.org](https://www.python.org/downloads/).

## 🛠️ Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/OSINT-tool.git
cd OSINT-tool
```

### Step 2: Create a Virtual Environment

**Windows:**
```bash
python -m venv .venv
```

**macOS/Linux:**
```bash
python3 -m venv .venv
```

### Step 3: Activate the Virtual Environment

**Windows (Command Prompt):**
```bash
.\.venv\Scripts\activate
```

**Windows (PowerShell):**
```bash
.\.venv\Scripts\Activate.ps1
```

**macOS/Linux:**
```bash
source .venv/bin/activate
```

You'll know it's activated when you see `(.venv)` at the beginning of your command prompt.

### Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

This will install all required packages including:
- `typer` - CLI framework
- `rich` - Terminal formatting
- `httpx` - HTTP client
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `openai` - OpenAI API client
- And more...

### Step 5: Verify Installation

Test that everything is working:

```bash
python cli.py --help
```

You should see the help menu with available commands.

## 🎯 Usage

### Quick Start - Web Interface (Recommended)

The easiest way to use the OSINT Tool is through the web interface. It provides a modern, user-friendly interface with real-time results.

#### Step 1: Start the Web Server

Make sure your virtual environment is activated, then run:

```bash
python simple_server.py
```

You should see output like:
```
OSINT Tool server running on http://localhost:8000
Press Ctrl+C to stop the server
```

#### Step 2: Access the Web Interface

Open your web browser and navigate to:
```
http://127.0.0.1:8000
```

#### Step 3: Use the Interface

The web interface has 5 main tabs:

1. **Domain Tab**: 
   - Enter a domain name (e.g., `example.com`)
   - Check WHOIS information, DNS records, and subdomains
   - Select which features to run with checkboxes

2. **IP Tab**: 
   - Enter an IP address (e.g., `8.8.8.8`)
   - Get geolocation, ISP details, and reverse DNS
   - Choose between basic and detailed analysis

3. **Username Tab**: 
   - Enter a username (e.g., `johndoe`)
   - Check availability across 13+ social media platforms
   - See which platforms the username exists on

4. **Email Tab**: 
   - Enter an email address (e.g., `user@example.com`)
   - Validate email syntax and check for Gravatar
   - Find social media accounts using the email username

5. **AI Tab**: 
   - Get AI-powered analysis of your findings
   - Ask questions about the gathered intelligence
   - Requires OpenAI API key (optional)

#### Step 4: Stop the Server

Press `Ctrl+C` in the terminal to stop the web server.

### Command Line Interface (CLI)

For quick checks or automation, you can also use the command line interface:

#### Domain Intelligence

```bash
# Basic domain lookup
python cli.py domain example.com

# Domain with subdomain discovery
python cli.py domain example.com --subdomains

# Domain with only DNS records (no WHOIS)
python cli.py domain example.com --no-whois

# Domain with only WHOIS (no DNS)
python cli.py domain example.com --no-dns
```

#### IP Address Analysis

```bash
# Basic IP lookup
python cli.py ip 8.8.8.8

# IP with only reverse DNS
python cli.py ip 8.8.8.8 --no-details

# IP with only geolocation details
python cli.py ip 8.8.8.8 --no-reverse
```

#### Username Hunting

```bash
# Check username across all platforms
python cli.py username johndoe

# Check specific platforms only
python cli.py username johndoe --sites twitter,github,instagram
```

#### Email Validation

```bash
# Validate email address
python cli.py email user@example.com
```

## 🤖 AI Features Setup

### Step 1: Get an OpenAI API Key

1. Visit [OpenAI Platform](https://platform.openai.com/api-keys)
2. Sign in or create an account
3. Click "Create new secret key"
4. Copy the generated key (starts with `sk-`)

### Step 2: Configure the API Key

**Option A: Environment Variable (Recommended)**

**Windows (Command Prompt):**
```bash
set OPENAI_API_KEY=sk-your-key-here
```

**Windows (PowerShell):**
```powershell
$env:OPENAI_API_KEY="sk-your-key-here"
```

**macOS/Linux:**
```bash
export OPENAI_API_KEY=sk-your-key-here
```

**Option B: .env File**
Create a `.env` file in the project root:
```
OPENAI_API_KEY=sk-your-key-here
```

**Option C: Web UI (Temporary)**
- Enter your API key directly in the AI tab
- No need to save it permanently

### Step 3: Use AI Features

1. **In the Web Interface:**
   - Go to the "AI" tab
   - Enter your target (domain, IP, username, etc.)
   - Select the type of analysis
   - Click "Summarize" for AI analysis
   - Ask follow-up questions with "Ask"

2. **AI Capabilities:**
   - Summarize gathered intelligence
   - Answer questions about findings
   - Provide context and insights
   - Identify potential security implications

## 🔧 Troubleshooting

### Common Installation Issues

**"No module named pip"**
```bash
python -m ensurepip --upgrade
python -m pip install --upgrade pip setuptools wheel
```

**Build errors on Windows**
```bash
# Install Microsoft Visual C++ Build Tools, or use:
pip install --only-binary=all -r requirements.txt
```

**Permission errors on macOS/Linux**
```bash
# Use sudo if needed:
sudo python3 -m pip install -r requirements.txt
```

### Common Runtime Issues

**"Module not found" errors**
- Ensure your virtual environment is activated
- Reinstall dependencies: `pip install -r requirements.txt`
- For the web server, make sure all required packages are installed: `pip install httpx whois dnspython`

**Web server won't start**
```bash
# Check if port 8000 is in use
# Try a different port:
python simple_server.py --port 8001

# If you get import errors, make sure dependencies are installed:
pip install -r requirements.txt

# Make sure you're in the correct directory:
cd OSINT-tool
python simple_server.py
```

**API key not working**
- Verify your OpenAI API key is correct
- Check your OpenAI account has credits
- Try entering the key directly in the web UI

**Slow or failed requests**
- Check your internet connection
- Some APIs may have rate limits
- Try again in a few minutes

### Getting Help

1. **Check error messages** in the terminal for specific issues
2. **Verify all dependencies** are installed: `pip list`
3. **Ensure virtual environment** is activated (you should see `(.venv)` in your prompt)
4. **Test internet connection** for API calls
5. **Check Python version** meets requirements: `python --version`

## 📚 Examples

### Domain Analysis Example

```bash
# Analyze a domain with all features
python cli.py domain google.com --subdomains
```

This will show:
- WHOIS registration details
- DNS records (A, AAAA, MX, NS, TXT, CNAME)
- Subdomains from certificate transparency logs

### Username Hunting Example

```bash
# Check if a username exists on popular platforms
python cli.py username johnsmith
```

This will check:
- Twitter/X, Instagram, Facebook, LinkedIn
- GitHub, GitLab, Bitbucket
- YouTube, Twitch, TikTok
- Reddit, Discord, Telegram
- And more...

### IP Analysis Example

```bash
# Get detailed information about an IP address
python cli.py ip 1.1.1.1
```

This will show:
- Geolocation (country, city, coordinates)
- ISP and organization information
- Reverse DNS (PTR record)
- Proxy/VPN detection

## 🔒 Security and Legal Notes

### Responsible Use
- This tool is for **legitimate OSINT research only**
- Respect rate limits and terms of service
- Don't use for malicious purposes
- Follow applicable laws and regulations

### Privacy
- API keys are stored locally only
- All requests are made from your machine
- No data is sent to external servers except for legitimate lookups

### Supported Platforms
The tool checks these platforms for username availability:
- **Social Media**: Twitter/X, Instagram, Facebook, LinkedIn, TikTok
- **Development**: GitHub, GitLab, Bitbucket
- **Gaming**: Twitch, Discord, Steam
- **Content**: YouTube, Reddit, Medium
- **Professional**: Stack Overflow, Behance, Dribbble
- **And more...**

## 🏗️ Project Structure

```
OSINT-tool/
├── osint_tool/
│   ├── __init__.py          # Package initialization
│   ├── __main__.py          # CLI entry point
│   ├── cli.py              # CLI commands and core logic
│   ├── webapp.py           # FastAPI web application (alternative)
│   └── web_static/
│       └── index.html      # Web interface
├── simple_server.py        # Simple HTTP server (recommended)
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

**Server Options:**
- **`simple_server.py`** - **Recommended**: Simple HTTP server with full API support
- **`webapp.py`** - Alternative: Full FastAPI server (more complex setup)
- **CLI only** - Use `python cli.py` for command-line only

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test both CLI and web interfaces
5. Submit a pull request

## 📄 License

This project is for educational and legitimate research purposes only. Use responsibly and in accordance with applicable laws and terms of service.

---

**Happy OSINT hunting! 🔍**


