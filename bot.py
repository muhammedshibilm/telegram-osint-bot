import os
import subprocess
import requests
import asyncio
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
import json
import re

# Load environment variables from .env file
load_dotenv()

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ADMIN_USER_IDS = os.getenv("ADMIN_USER_IDS", "").split(",")

# Helper function: run a command and return its output
def run_command(cmd_list, label, timeout=30):
    try:
        result = subprocess.check_output(cmd_list, stderr=subprocess.STDOUT, timeout=timeout)
        output = result.decode()
        return f"{label}:\n{output}"
    except subprocess.TimeoutExpired:
        return f"{label} error: Command timed out"
    except Exception as e:
        return f"{label} error: {e}"

# Helper function to truncate long messages
def truncate_message(text, max_length=4000):
    if len(text) > max_length:
        return text[:max_length] + "\n...Output truncated."
    return text

# Helper function to validate IP address
def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

# Helper function to validate domain
def is_valid_domain(domain):
    pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    return pattern.match(domain) is not None

# /start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("📋 Commands", callback_data='show_commands')],
        [InlineKeyboardButton("ℹ️ About", callback_data='show_about')],
        [InlineKeyboardButton("🔧 Tools", callback_data='show_tools')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = (
        "🔍 *Welcome to OSINT Recon Bot!*\n\n"
        "Your all-in-one network reconnaissance and threat intelligence tool.\n\n"
        "Use /help to see available commands or click buttons below:"
    )
    await update.message.reply_text(welcome_text, parse_mode="Markdown", reply_markup=reply_markup)

# Callback query handler
async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == 'show_commands':
        help_text = (
            "📋 *Available Commands:*\n\n"
            "*Network Tools:*\n"
            "/whois <target> - WHOIS lookup\n"
            "/traceroute <target> - Trace route\n"
            "/dig <domain> - DNS lookup\n"
            "/nslookup <domain> - Alternative DNS lookup\n"
            "/ping <target> - Ping a host\n"
            "/portscan <ip> - Quick port scan\n"
            "/brute <ip> - Full port scan (masscan)\n\n"
            "*IP Intelligence:*\n"
            "/ipinfo <ip> - IPInfo lookup\n"
            "/geoip <ip> - Geo-location lookup\n"
            "/abuseip <ip> - AbuseIPDB report\n"
            "/virustotal <ip> - VirusTotal report\n"
            "/torvpn <ip> - Check for TOR/VPN/proxy\n"
            "/shodan <ip> - Shodan lookup\n"
            "/reversedns <ip> - Reverse DNS lookup\n\n"
            "*Security Tools:*\n"
            "/emailleaks <email> - Check email leaks\n"
            "/sslcheck <domain> - SSL certificate info\n"
            "/headers <url> - HTTP headers analysis\n"
            "/subdomain <domain> - Find subdomains\n\n"
            "*Comprehensive Reports:*\n"
            "/fullreport <ip> - Complete threat analysis\n"
            "/compare <ip1> <ip2> - Compare two IPs\n\n"
            "*Utility:*\n"
            "/help - Show this help\n"
            "/about - About this bot"
        )
        await query.edit_message_text(help_text, parse_mode="Markdown")
    
    elif query.data == 'show_about':
        about_text = (
            "ℹ️ *About OSINT Recon Bot*\n\n"
            "Version: 2.0\n"
            "Purpose: Network reconnaissance and threat intelligence\n\n"
            "Features:\n"
            "✓ Network scanning and analysis\n"
            "✓ IP reputation checking\n"
            "✓ Email leak detection\n"
            "✓ SSL/TLS analysis\n"
            "✓ Subdomain enumeration\n"
            "✓ Comprehensive threat reports\n\n"
            "⚠️ Use responsibly and only on authorized targets!"
        )
        await query.edit_message_text(about_text, parse_mode="Markdown")
    
    elif query.data == 'show_tools':
        tools_text = (
            "🔧 *Integrated Tools:*\n\n"
            "• WHOIS\n"
            "• Traceroute\n"
            "• Dig/Nslookup\n"
            "• Masscan\n"
            "• AbuseIPDB\n"
            "• VirusTotal\n"
            "• Shodan\n"
            "• IPInfo.io\n"
            "• LeakCheck\n"
            "• Custom SSL checker\n\n"
            "All tools are integrated for quick reconnaissance."
        )
        await query.edit_message_text(tools_text, parse_mode="Markdown")

# /help command
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "📋 *Available Commands:*\n\n"
        "*Network Tools:*\n"
        "/whois <target> - WHOIS lookup\n"
        "/traceroute <target> - Trace route\n"
        "/dig <domain> - DNS lookup\n"
        "/nslookup <domain> - Alternative DNS lookup\n"
        "/ping <target> - Ping a host\n"
        "/portscan <ip> - Quick port scan\n"
        "/brute <ip> - Full port scan\n\n"
        "*IP Intelligence:*\n"
        "/ipinfo <ip> - IPInfo lookup\n"
        "/geoip <ip> - Geo-location\n"
        "/abuseip <ip> - AbuseIPDB report\n"
        "/virustotal <ip> - VirusTotal report\n"
        "/torvpn <ip> - TOR/VPN check\n"
        "/shodan <ip> - Shodan lookup\n"
        "/reversedns <ip> - Reverse DNS\n\n"
        "*Security Tools:*\n"
        "/emailleaks <email> - Email leaks\n"
        "/sslcheck <domain> - SSL info\n"
        "/headers <url> - HTTP headers\n"
        "/subdomain <domain> - Subdomains\n\n"
        "*Reports:*\n"
        "/fullreport <ip> - Full analysis\n"
        "/compare <ip1> <ip2> - Compare IPs"
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")

# /whois command
async def whois(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /whois <target>")
        return
    
    target = context.args[0]
    await update.message.reply_text("🔍 Running WHOIS lookup...")
    
    output = run_command(["whois", target], "Whois")
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /traceroute command
async def traceroute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /traceroute <target>")
        return
    
    target = context.args[0]
    await update.message.reply_text("🔍 Running traceroute...")
    
    output = run_command(["traceroute", "-m", "15", target], "Traceroute", timeout=60)
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /dig command
async def dig(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /dig <domain>")
        return
    
    domain = context.args[0]
    await update.message.reply_text("🔍 Running DNS lookup...")
    
    output = run_command(["dig", domain], "Dig")
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /nslookup command
async def nslookup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /nslookup <domain>")
        return
    
    domain = context.args[0]
    await update.message.reply_text("🔍 Running nslookup...")
    
    output = run_command(["nslookup", domain], "Nslookup")
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /ping command
async def ping(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /ping <target>")
        return
    
    target = context.args[0]
    await update.message.reply_text("🔍 Pinging host...")
    
    output = run_command(["ping", "-c", "4", target], "Ping")
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /reversedns command
async def reversedns(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /reversedns <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Running reverse DNS lookup...")
    
    output = run_command(["host", ip], "Reverse DNS")
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /ipinfo command
async def ipinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /ipinfo <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Fetching IP info...")
    
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        data = res.json()
        output = (
            f"*IP Information:*\n"
            f"IP: `{data.get('ip', 'N/A')}`\n"
            f"City: {data.get('city', 'N/A')}\n"
            f"Region: {data.get('region', 'N/A')}\n"
            f"Country: {data.get('country', 'N/A')}\n"
            f"Location: {data.get('loc', 'N/A')}\n"
            f"Org: {data.get('org', 'N/A')}\n"
            f"Timezone: {data.get('timezone', 'N/A')}"
        )
    except Exception as e:
        output = f"IPInfo error: {e}"
    
    await update.message.reply_text(output, parse_mode="Markdown")

# /geoip command
async def geoip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /geoip <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Fetching geo-location...")
    
    try:
        res = requests.get(f"https://geolocation-db.com/json/{ip}&position=true", timeout=10)
        data = res.json()
        output = f"GeoIP:\n{json.dumps(data, indent=2)}"
    except Exception as e:
        output = f"GeoIP error: {e}"
    
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /portscan command (quick scan)
async def portscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /portscan <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Running quick port scan on common ports...")
    
    # Scan common ports
    common_ports = "80,443,22,21,25,53,3306,3389,8080,8443"
    output = run_command(["masscan", ip, f"-p{common_ports}", "--rate", "1000"], "Port Scan", timeout=30)
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /brute command (full scan)
async def brute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /brute <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Running full port scan... (this may take a while)")
    
    output = run_command(["masscan", ip, "-p1-1000", "--rate", "1000"], "Masscan", timeout=120)
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /emailleaks command
async def emailleaks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /emailleaks <email>")
        return
    
    email = context.args[0]
    await update.message.reply_text("🔍 Checking for email leaks...")
    
    try:
        res = requests.get(f"https://leakcheck.net/api/public?check={email}", timeout=10)
        if res.status_code == 200:
            output = f"Email Leak Report:\n{res.text}"
        else:
            output = f"LeakCheck error: {res.status_code}"
    except Exception as e:
        output = f"Email leak check error: {e}"
    
    output = truncate_message(output)
    await update.message.reply_text(f"```\n{output}\n```", parse_mode="Markdown")

# /abuseip command
async def abuseip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /abuseip <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Fetching AbuseIPDB report...")
    
    try:
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        res = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers, timeout=10)
        data = res.json()['data']
        output = (
            f"*AbuseIPDB Report:*\n"
            f"IP: `{data['ipAddress']}`\n"
            f"Abuse Score: {data['abuseConfidenceScore']}%\n"
            f"Total Reports: {data['totalReports']}\n"
            f"Country: {data['countryCode']}\n"
            f"Usage: {data.get('usageType', 'N/A')}\n"
            f"ISP: {data.get('isp', 'N/A')}"
        )
    except Exception as e:
        output = f"AbuseIPDB error: {e}"
    
    await update.message.reply_text(output, parse_mode="Markdown")

# /virustotal command
async def virustotal(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /virustotal <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Fetching VirusTotal report...")
    
    try:
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=10)
        data = res.json()['data']['attributes']
        stats = data['last_analysis_stats']
        output = (
            f"*VirusTotal Report:*\n"
            f"🔴 Malicious: {stats['malicious']}\n"
            f"🟡 Suspicious: {stats['suspicious']}\n"
            f"🟢 Harmless: {stats['harmless']}\n"
            f"⚪ Undetected: {stats['undetected']}\n"
            f"ASN: {data.get('asn', 'N/A')}\n"
            f"Org: {data.get('as_owner', 'N/A')}"
        )
    except Exception as e:
        output = f"VirusTotal error: {e}"
    
    await update.message.reply_text(output, parse_mode="Markdown")

# /torvpn command
async def torvpn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /torvpn <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Checking for TOR/VPN/proxy...")
    
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        data = res.json()
        sec = data.get("security", {})
        is_vpn = sec.get("vpn", False)
        is_proxy = sec.get("proxy", False)
        is_tor = sec.get("tor", False)
        
        vpn_emoji = "✅" if is_vpn else "❌"
        proxy_emoji = "✅" if is_proxy else "❌"
        tor_emoji = "✅" if is_tor else "❌"
        
        output = (
            f"*TOR/VPN Detection:*\n"
            f"VPN: {vpn_emoji} {is_vpn}\n"
            f"Proxy: {proxy_emoji} {is_proxy}\n"
            f"TOR: {tor_emoji} {is_tor}"
        )
    except Exception as e:
        output = f"TOR/VPN detection error: {e}"
    
    await update.message.reply_text(output, parse_mode="Markdown")

# /shodan command
async def shodan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /shodan <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Fetching Shodan report...")
    
    if not SHODAN_API_KEY:
        await update.message.reply_text("⚠️ Shodan API key not configured")
        return
    
    try:
        res = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=10)
        data = res.json()
        
        ports = ", ".join(map(str, data.get('ports', [])))
        vulns = len(data.get('vulns', []))
        
        output = (
            f"*Shodan Report:*\n"
            f"IP: `{data.get('ip_str', 'N/A')}`\n"
            f"Org: {data.get('org', 'N/A')}\n"
            f"OS: {data.get('os', 'N/A')}\n"
            f"Open Ports: {ports or 'None'}\n"
            f"Vulnerabilities: {vulns}\n"
            f"Last Update: {data.get('last_update', 'N/A')}"
        )
    except Exception as e:
        output = f"Shodan error: {e}"
    
    await update.message.reply_text(output, parse_mode="Markdown")

# /sslcheck command
async def sslcheck(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /sslcheck <domain>")
        return
    
    domain = context.args[0]
    await update.message.reply_text("🔍 Checking SSL certificate...")
    
    try:
        import ssl
        import socket
        from datetime import datetime
        
        context_ssl = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context_ssl.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                output = (
                    f"*SSL Certificate Info:*\n"
                    f"Domain: {subject.get('commonName', 'N/A')}\n"
                    f"Issuer: {issuer.get('organizationName', 'N/A')}\n"
                    f"Expires: {expires.strftime('%Y-%m-%d')}\n"
                    f"Version: {cert.get('version', 'N/A')}\n"
                    f"Serial: {cert.get('serialNumber', 'N/A')}"
                )
    except Exception as e:
        output = f"SSL check error: {e}"
    
    await update.message.reply_text(output, parse_mode="Markdown")

# /headers command
async def headers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /headers <url>")
        return
    
    url = context.args[0]
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    await update.message.reply_text("🔍 Fetching HTTP headers...")
    
    try:
        res = requests.head(url, timeout=10, allow_redirects=True)
        headers_text = "\n".join([f"{k}: {v}" for k, v in res.headers.items()])
        output = f"*HTTP Headers:*\n```\n{headers_text}\n```"
        output = truncate_message(output)
    except Exception as e:
        output = f"Headers error: {e}"
    
    await update.message.reply_text(output, parse_mode="Markdown")

# /subdomain command
async def subdomain(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /subdomain <domain>")
        return
    
    domain = context.args[0]
    await update.message.reply_text("🔍 Finding subdomains (using crt.sh)...")
    
    try:
        res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        data = res.json()
        subdomains = set()
        for entry in data[:50]:  # Limit to 50
            name = entry.get('name_value', '')
            if '\n' in name:
                subdomains.update(name.split('\n'))
            else:
                subdomains.add(name)
        
        output = "*Subdomains Found:*\n" + "\n".join(sorted(subdomains)[:30])
        output = truncate_message(output)
    except Exception as e:
        output = f"Subdomain enumeration error: {e}"
    
    await update.message.reply_text(output, parse_mode="Markdown")

# /fullreport command
async def fullreport(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /fullreport <ip>")
        return
    
    ip = context.args[0]
    await update.message.reply_text("🔍 Generating comprehensive threat report... This will take a moment.")
    
    report = f"*📊 Comprehensive Threat Report for {ip}*\n\n"
    
    # IPInfo
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        data = res.json()
        report += f"*Basic Info:*\n"
        report += f"Location: {data.get('city', 'N/A')}, {data.get('country', 'N/A')}\n"
        report += f"Org: {data.get('org', 'N/A')}\n\n"
    except:
        report += "*Basic Info:* Error\n\n"
    
    # AbuseIPDB
    if ABUSEIPDB_API_KEY:
        try:
            headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
            res = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers, timeout=10)
            data = res.json()['data']
            report += f"*Abuse Score:* {data['abuseConfidenceScore']}%\n"
            report += f"*Total Reports:* {data['totalReports']}\n\n"
        except:
            report += "*Abuse Check:* Error\n\n"
    
    # VirusTotal
    if VT_API_KEY:
        try:
            headers = {"x-apikey": VT_API_KEY}
            res = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=10)
            data = res.json()['data']['attributes']
            stats = data['last_analysis_stats']
            report += f"*VirusTotal:*\n"
            report += f"Malicious: {stats['malicious']} | Suspicious: {stats['suspicious']}\n\n"
        except:
            report += "*VirusTotal:* Error\n\n"
    
    # TOR/VPN Check
    try:
        res = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
        data = res.json()
        sec = data.get("security", {})
        report += f"*Security:*\n"
        report += f"VPN: {sec.get('vpn', False)} | TOR: {sec.get('tor', False)}\n\n"
    except:
        report += "*Security Check:* Error\n\n"
    
    report += "✅ Report Complete"
    report = truncate_message(report)
    await update.message.reply_text(report, parse_mode="Markdown")

# /compare command
async def compare(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /compare <ip1> <ip2>")
        return
    
    ip1, ip2 = context.args[0], context.args[1]
    await update.message.reply_text("🔍 Comparing IPs...")
    
    comparison = f"*IP Comparison*\n\n"
    
    for ip in [ip1, ip2]:
        try:
            res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            data = res.json()
            comparison += f"*{ip}:*\n"
            comparison += f"Location: {data.get('city', 'N/A')}, {data.get('country', 'N/A')}\n"
            comparison += f"Org: {data.get('org', 'N/A')}\n\n"
        except:
            comparison += f"*{ip}:* Error fetching data\n\n"
    
    comparison = truncate_message(comparison)
    await update.message.reply_text(comparison, parse_mode="Markdown")

# /about command
async def about(update: Update, context: ContextTypes.DEFAULT_TYPE):
    about_text = (
        "ℹ️ *OSINT Recon Bot v2.0*\n\n"
        "Advanced network reconnaissance and threat intelligence tool.\n\n"
        "*Features:*\n"
        "✓ Network scanning\n"
        "✓ IP reputation\n"
        "✓ Email leak detection\n"
        "✓ SSL/TLS analysis\n"
        "✓ Subdomain enumeration\n"
        "✓ Comprehensive reports\n\n"
        "⚠️ *Use responsibly!*"
    )
    await update.message.reply_text(about_text, parse_mode="Markdown")

def main():
    application = Application.builder().token(TOKEN).build()

    # Register all handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("whois", whois))
    application.add_handler(CommandHandler("traceroute", traceroute))
    application.add_handler(CommandHandler("dig", dig))
    application.add_handler(CommandHandler("nslookup", nslookup))
    application.add_handler(CommandHandler("ping", ping))
    application.add_handler(CommandHandler("portscan", portscan))
    application.add_handler(CommandHandler("brute", brute))
    application.add_handler(CommandHandler("emailleaks", emailleaks))
    application.add_handler(CommandHandler("abuseip", abuseip))
    application.add_handler(CommandHandler("virustotal", virustotal))
    application.add_handler(CommandHandler("torvpn", torvpn))
    application.add_handler(CommandHandler("shodan", shodan))
    application.add_handler(CommandHandler("sslcheck", sslcheck))
    application.add_handler(CommandHandler("headers", headers))
    application.add_handler(CommandHandler("subdomain", subdomain))
    application.add_handler(CommandHandler("fullreport", fullreport))
    application.add_handler(CommandHandler("compare", compare))
    application.add_handler(CommandHandler("about", about))

    application.add_handler(CallbackQueryHandler(button_callback))

   
    application.run_polling()

if __name__ == "__main__":
    main()
