from flask import Flask, render_template, request
import re
import dns.resolver
import whois
import subprocess

app = Flask(__name__)

def is_domain_or_ipv4(input_str):
    ipv4_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    domain_pattern = r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$"
    if re.match(ipv4_pattern, input_str):
        return "ipv4"
    elif re.match(domain_pattern, input_str):
        return "domain"
    else:
        return None

def get_dns_info(domain):
    dns_results = {}
    resolver = dns.resolver.Resolver()
    # A record
    try:
        dns_results['A'] = [r.to_text() for r in resolver.resolve(domain, 'A')]
    except Exception:
        dns_results['A'] = []
    # IPv6/AAAA record for main domain
    try:
        dns_results['AAAA'] = [r.to_text() for r in resolver.resolve(domain, 'AAAA')]
    except Exception:
        dns_results['AAAA'] = []
    # WWW A record
    try:
        dns_results['WWW_A'] = [r.to_text() for r in resolver.resolve("www." + domain, 'A')]
    except Exception:
        dns_results['WWW_A'] = []
    # MX record
    try:
        dns_results['MX'] = [r.to_text() for r in resolver.resolve(domain, 'MX')]
    except Exception:
        dns_results['MX'] = []
    # TXT record
    try:
        dns_results['TXT'] = [r.to_text() for r in resolver.resolve(domain, 'TXT')]
    except Exception:
        dns_results['TXT'] = []
    # NS record
    try:
        ns_records = [r.to_text() for r in resolver.resolve(domain, "NS")]
        dns_results['NS'] = ns_records
        dns_results['cloudflare'] = any('cloudflare' in ns.lower() for ns in ns_records)
    except Exception:
        dns_results['NS'] = []
        dns_results['cloudflare'] = False
    # DNSSEC check
    try:
        dnskey = resolver.resolve(domain, 'DNSKEY')
        dns_results['dnssec'] = True if dnskey else False
    except Exception:
        dns_results['dnssec'] = False
    return dns_results

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0] if expiration else None
        # Fix status: should be always a list
        status = w.status
        if status is None:
            status_list = []
        elif isinstance(status, str):
            status_list = [status]
        else:
            status_list = status
        whois_info = {
            "registrar": w.registrar if w.registrar else "Unknown",
            "expiration": str(expiration) if expiration else "Unknown",
            "statuses": status_list,
            "raw": str(w.text) if hasattr(w, "text") and w.text else "",
        }
    except Exception:
        whois_info = {
            "registrar": "Unknown",
            "expiration": "Unknown",
            "statuses": [],
            "raw": "",
        }
    return whois_info

def get_curl_headers(domain):
    scheme = "https" if is_domain_or_ipv4(domain) == "domain" else "http"
    url = f"{scheme}://{domain}"
    try:
        headers = subprocess.run(
            ["curl", "-s", "-D", "-", "-o", "/dev/null", url],
            capture_output=True, text=True, timeout=15
        ).stdout
    except Exception as e:
        headers = str(e)
    return headers

def analyze_headers(headers):
    analysis = []
    required = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy'
    ]
    for h in required:
        if h.lower() not in headers.lower():
            analysis.append(f"Missing security header: {h}")
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
    error_msg = None
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        input_type = is_domain_or_ipv4(domain)
        if domain and not input_type:
            error_msg = "Please enter a valid domain name (example.com) or IPv4 address (e.g. 8.8.8.8)."
        else:
            if domain and input_type:
                dns_data = get_dns_info(domain)
                whois_info = get_whois_info(domain)
                headers = get_curl_headers(domain)
                analysis = analyze_headers(headers)
                domain_info = {
                    "dns": dns_data,
                    "whois": whois_info,
                }
                curl_info = {
                    "headers": headers,
                    "analysis": analysis,
                }
    return render_template("index.html",
        domain_info=domain_info,
        curl_info=curl_info,
        domain=domain,
        error_msg=error_msg
    )

if __name__ == "__main__":
    app.run(debug=True)