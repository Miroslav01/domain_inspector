from flask import Flask, render_template, request
import subprocess
import re

app = Flask(__name__)

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return result.stdout
    except Exception as e:
        return str(e)

def get_dns_info(domain):
    dns = {}
    # A record
    dns['A'] = run_cmd(f'dig +short {domain} A')
    # MX record
    dns['MX'] = run_cmd(f'dig +short {domain} MX')
    # TXT record
    dns['TXT'] = run_cmd(f'dig +short {domain} TXT')
    # NS record
    ns = run_cmd(f'dig +short {domain} NS')
    dns['NS'] = ns
    # Cloudflare check
    dns['cloudflare'] = False
    if ns and any('cloudflare' in line.lower() for line in ns.splitlines()):
        dns['cloudflare'] = True
    # www version
    dns['WWW_A'] = run_cmd(f'dig +short www.{domain} A')
    return dns

def parse_whois(whois_raw):
    whois = {}
    # Registrar
    m = re.search(r'Registrar:\s*(.*)', whois_raw)
    whois['registrar'] = m.group(1).strip() if m else 'Unknown'
    # Expiration
    m = re.search(r'Expir\w* Date:\s*(.*)', whois_raw)
    whois['expiration'] = m.group(1).strip() if m else 'Unknown'
    # Status
    statuses = re.findall(r'Status:\s*(.*)', whois_raw)
    whois['statuses'] = statuses
    whois['hold'] = any('clienthold' in s.lower() or 'serverhold' in s.lower() for s in statuses)
    # Expired/Redemption
    expired = False
    if whois['expiration'] != 'Unknown':
        from datetime import datetime
        try:
            exp = datetime.strptime(whois['expiration'][:10], "%Y-%m-%d")
            if exp < datetime.utcnow():
                expired = True
        except Exception:
            pass
    whois['expired'] = expired
    whois['redemption'] = any('redemption' in s.lower() for s in statuses)
    return whois

def get_whois_info(domain):
    whois_raw = run_cmd(f'whois {domain}')
    return parse_whois(whois_raw), whois_raw

def get_curl_headers(url):
    headers = run_cmd(f'curl -s -D - -o /dev/null {url}')
    return headers

def analyze_headers(headers):
    analysis = []
    # Security headers
    required = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy']
    for h in required:
        if h.lower() not in headers.lower():
            analysis.append(f"Missing security header: {h}")
    # Caching
    if 'cache-control' not in headers.lower():
        analysis.append("Missing caching header: Cache-Control")
    else:
        cc = re.search(r'Cache-Control: (.*)', headers, re.IGNORECASE)
        if cc:
            analysis.append(f"Cache-Control: {cc.group(1).strip()}")
    return analysis

@app.route("/", methods=["GET", "POST"])
def index():
    domain_info = None
    curl_info = None
    domain = ""
    url = ""
    if request.method == "POST":
        domain = request.form.get("domain")
        url = request.form.get("url")
        if domain:
            dns = get_dns_info(domain)
            whois, whois_raw = get_whois_info(domain)
            domain_info = {
                "dns": dns,
                "whois": whois,
                "whois_raw": whois_raw,
            }
        if url:
            headers = get_curl_headers(url)
            analysis = analyze_headers(headers)
            curl_info = {
                "headers": headers,
                "analysis": analysis,
            }
    return render_template("index.html", domain_info=domain_info, curl_info=curl_info, domain=domain, url=url)

if __name__ == "__main__":
    app.run(debug=True)