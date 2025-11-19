# 🔍 Telegram OSINT Recon Bot

Advanced network reconnaissance and threat intelligence bot for Telegram.

## Features

### Network Tools
- 🌐 WHOIS lookup
- 📡 Traceroute
- 🔎 DNS lookup (dig/nslookup)
- 📶 Ping
- 🔓 Port scanning (quick & full)
- 🔄 Reverse DNS lookup

### IP Intelligence
- 📍 IP geolocation
- ⚠️ AbuseIPDB reputation
- 🛡️ VirusTotal scanning
- 🔐 TOR/VPN/Proxy detection
- 🔍 Shodan integration

### Security Tools
- 📧 Email leak detection
- 🔒 SSL certificate analysis
- 📋 HTTP headers inspection
- 🌳 Subdomain enumeration

### Advanced Features
- 📊 Comprehensive threat reports
- ⚖️ IP comparison
- 📈 Interactive interface

## Quick Start

### Using Docker Compose (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/muhammedshibilm/telegram-osint-bot.git
cd telegram-osint-bot
```

2. create `.env` file and add your configurations:
```bash
echo "TELEGRAM_BOT_TOKEN=your_telegram_bot_token \n ABUSEIPDB_API_KEY=your_abuseipdb_api_key \n VT_API_KEY=your_virustotal_api_key \n SHODAN_API_KEY=your_shodan_api_key \n ADMIN_USER_IDS=your_admin_user_ids" > .env
```

3. Add your Telegram bot token (required):
   - Message [@BotFather](https://t.me/botfather)
   - Send `/newbot` and follow instructions
   - Copy token to `.env` file

4.  Make the deployment script executable:
```bash
chmod +x deploy.sh 
```  

5. Run the deployment script make sure you have docker and docker-compose installed:
```bash
./deploy.sh
````


Manual Installation

1. Install dependencies:
```bash
sudo apt-get install whois traceroute dnsutils masscan
pip install -r requirements.txt
```

2. Configure `.env` file

3. Run the bot:
```bash
python bot.py
```

## API Keys (Optional)

Get free API keys to enable additional features:

- **AbuseIPDB**: https://www.abuseipdb.com/register
- **VirusTotal**: https://www.virustotal.com/gui/join-us
- **Shodan**: https://account.shodan.io/register

Add them to your `.env` file.

## Commands
```
/start - Welcome message
/help - List all commands
/whois <target> - WHOIS lookup
/traceroute <target> - Trace route
/dig <domain> - DNS lookup
/ping <target> - Ping host
/ipinfo <ip> - IP information
/portscan <ip> - Quick port scan
/emailleaks <email> - Check email leaks
/abuseip <ip> - Abuse reputation
/virustotal <ip> - VirusTotal scan
/shodan <ip> - Shodan lookup
/sslcheck <domain> - SSL certificate info
/subdomain <domain> - Find subdomains
/fullreport <ip> - Comprehensive analysis
/compare <ip1> <ip2> - Compare two IPs
```

## Docker Commands if uisng docker compose new versoin
```bash
# Start bot
docker compose up -d

# Stop bot
docker compose down

# Restart bot
docker compose restart

# View logs
docker compose logs -f

# Rebuild after changes
docker compose up -d --build
```


## Security Notes

⚠️ **Important:**
- Only use on authorized targets
- Respect rate limits
- Keep API keys private
- Use responsibly

## Troubleshooting

**Bot not responding:**
- Check if token is correct
- Verify bot is running: `docker compose ps`
- Check logs: `docker compose logs`

**Commands failing:**
- Ensure system tools are installed
- Check API keys are valid
- Verify network connectivity

**Permission errors:**
- Masscan requires root/CAP_NET_RAW
- Docker compose includes necessary capabilities

## License

MIT License - Use at your own risk

## Contributing

Pull requests welcome! Please ensure code follows best practices.

## Support

For issues, open a GitHub issue or contact the maintainer.
```

## 7. **.gitignore**
```
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Environment
.env
.env.local

# Logs
logs/
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

