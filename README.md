# OSINT Tool

A sleek Python OSINT toolkit with a no-nonsense CLI and a modern web UI (dark by default, obviously).

## Features

- **Domain Intelligence**: WHOIS lookup, DNS records, subdomain enumeration
- **IP Analysis**: Geolocation, reverse DNS, ISP details
- **Username Hunting**: Check 20+ social media platforms for username availability
- **Email Validation**: Syntax check, Gravatar lookup, social media presence
- **GitHub Recon**: User profiles, repositories, activity analysis
- **AI Integration**: OpenAI-powered summarization and Q&A over gathered intel
- **Web Interface**: Modern dark-themed UI with real-time results

## Quick Start

### Prerequisites
- Python 3.8+ installed
- Git (for cloning)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd OSINT-tool
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   ```

3. **Activate virtual environment**
   
   **Windows:**
   ```bash
   .\.venv\Scripts\activate
   ```
   
   **macOS/Linux:**
   ```bash
   source .venv/bin/activate
   ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface

The CLI provides quick OSINT checks from your terminal:

```bash
# Domain intelligence
python -m osint_tool domain example.com

# IP analysis
python -m osint_tool ip 8.8.8.8

# Username hunting
python -m osint_tool username johndoe

# Email validation
python -m osint_tool email user@example.com

# GitHub recon
python -m osint_tool github torvalds
```

### Web Interface

For a more comprehensive experience with real-time results:

#### Option 1: FastAPI Server (Recommended)

1. **Start the web server**
   ```bash
   python -m osint_tool.webapp
   ```

2. **Open your browser**
   Navigate to: `http://127.0.0.1:8000`

#### Option 2: Simple HTTP Server

1. **Start the simple server**
   ```bash
   python simple_server.py
   ```

2. **Open your browser**
   Navigate to: `http://127.0.0.1:8000`

**Note**: The simple server includes additional features like phone number lookup that aren't available in the FastAPI version.

3. **Use the interface**
   - Switch between tabs for different OSINT functions
   - Enter your target (domain, IP, username, email, etc.)
   - Click "Run" to execute the search
   - View results in real-time with clickable links

### AI Features (Optional)

To enable AI-powered analysis:

1. **Get an OpenAI API key**
   - Visit [OpenAI Platform](https://platform.openai.com/api-keys)
   - Create a new API key

2. **Configure the API key**
   
   **Option A: Environment variable**
   ```bash
   # Windows
   set OPENAI_API_KEY=sk-your-key-here
   
   # macOS/Linux
   export OPENAI_API_KEY=sk-your-key-here
   ```
   
   **Option B: .env file**
   Create a `.env` file in the project root:
   ```
   OPENAI_API_KEY=sk-your-key-here
   ```
   
   **Option C: Web UI**
   - Enter your API key directly in the AI tab
   - No need to save it permanently

3. **Use AI features**
   - Go to the "AI" tab in the web interface
   - Enter your target and select the type
   - Click "Summarize" for AI analysis
   - Ask follow-up questions with "Ask"

## Supported Platforms

### Username Hunting
- Twitter/X, Instagram, Facebook, LinkedIn
- GitHub, GitLab, Bitbucket
- YouTube, Twitch, TikTok
- Reddit, Discord, Telegram
- And 10+ more platforms

### Email Features
- Syntax validation
- Gravatar profile lookup
- Social media presence detection

### Domain Intelligence
- WHOIS registration details
- DNS records (A, AAAA, MX, NS, TXT, CNAME)
- Certificate transparency subdomain enumeration

### IP Analysis
- Geolocation data
- ISP and organization info
- Reverse DNS lookup
- Proxy/VPN detection

## Troubleshooting

### Common Issues

**"No module named pip"**
```bash
python -m ensurepip --upgrade
python -m pip install --upgrade pip setuptools wheel
```

**Build errors on Windows**
- Install Microsoft Visual C++ Build Tools
- Or use the pre-built wheels: `pip install --only-binary=all -r requirements.txt`

**API key not working**
- Verify your OpenAI API key is correct
- Check your account has credits
- Try entering the key directly in the web UI

**Web server won't start**
- Ensure you're in the virtual environment
- Check port 8000 isn't already in use
- Try a different port: `uvicorn osint_tool.webapp:app --port 8001`

### Getting Help

1. Check the error messages in the terminal
2. Verify all dependencies are installed
3. Ensure you're using the virtual environment
4. Check your internet connection for API calls

## Development

### Project Structure
```
OSINT-tool/
├── osint_tool/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py          # CLI commands and core logic
│   ├── webapp.py       # FastAPI web application
│   └── web_static/
│       └── index.html  # Web interface
├── simple_server.py    # Simple HTTP server (alternative)
├── requirements.txt    # Python dependencies
└── README.md
```

### Adding New Features
1. Extend the CLI functions in `cli.py`
2. Add corresponding API endpoints in `webapp.py`
3. Update the web interface in `index.html`
4. Test both CLI and web interfaces

## Security Notes

- This tool is for legitimate OSINT research only
- Respect rate limits and terms of service
- Don't use for malicious purposes
- API keys are stored locally only
- All requests are made from your machine

## License

This project is for educational and legitimate research purposes only. Use responsibly and in accordance with applicable laws and terms of service.


