from flask import Flask, request, render_template_string
import socket, re, subprocess
import dns.resolver
import whois

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Domain Check Tool</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { display: flex; }
        .left { flex: 3; margin-right: 20px; }
        .right { flex: 1; border: 1px solid #ccc; padding: 10px; }
        .panel { border: 1px solid #ccc; padding: 10px; margin-top: 20px; }
        h2 { margin-bottom: 5px; text-decoration: underline; }
        pre { margin: 0; white-space: pre-wrap; }
        .record-table { display: table; }
        .record-row { display: table-row; }
        .record-cell { display: table-cell; padding: 2px 15px 2px 0; }
        .domain-box { border: 1px solid #ccc; padding: 8px; margin-top: 20px; font-weight: bold; }
        .issue { color: red; margin-bottom: 5px; }
    </style>
</head>
<body>
    <h1>Domain Diagnostics</h1>
    <form method="POST">
        <input type="text" name="domain" placeholder="Enter domain" value="{{ domain if domain else '' }}">
        <input type="submit" value="Check">
    </form>

    {% if error %}
        <div class="panel"><b>{{ error }}</b></div>
    {% endif %}

    {% if domain and not error %}
    <div class="container">
        <div class="left">
            <div class="domain-box">Domain Checked: {{ domain }}</div>

            <div class="panel">
                <h2>DNS Results</h2>
                <div class="record-table">
                    {% for label, result in dns_results.items() %}
                        <div class="record-row">
                            <div class="record-cell"><b>{{ label }}:</b></div>
                            <div class="record-cell">
                                {% if result %} 
                                    {% for r in result %}{{ r }}<br>{% endfor %}
                                {% else %} -
                                {% endif %}
                            </div>
                        </div>
                    {% endfor %}
                </div>
            </div>

            <div class="panel">
                <h2>WHOIS Results</h2>
                <b>Registrar:</b> {{ whois_data.registrar if whois_data else "N/A" }}<br>
                <b>Creation Date:</b> {{ whois_data.creation_date if whois_data else "N/A" }}<br>
                <br>
                <div style="display:flex; gap:40px;">
                    <div>
                        <b>WHOIS Nameservers:</b><br>
                        {% if whois_ns %}
                            {% for ns in whois_ns %}{{ ns }}<br>{% endfor %}
                        {% else %}N/A
                        {% endif %}
                    </div>
                    <div>
                        <b>DNS NS Records:</b><br>
                        {% if dns_results["NS Records"] %}
                            {% for ns in dns_results["NS Records"] %}{{ ns }}<br>{% endfor %}
                        {% else %}N/A
                        {% endif %}
                    </div>
                </div>
            </div>

            <div class="panel">
                <h2>HTTP Results</h2>
                <b>Response Headers:</b><br>
                <pre>{{ curl_output }}</pre>
                <br>
                <b>Missing Security Headers:</b><br>
                {% if missing_headers %}
                    {% for h in missing_headers %}{{ h }}<br>{% endfor %}
                {% else %}
                    None
                {% endif %}
            </div>
        </div>

        <div class="right">
            <h2>Issues Found</h2>
            {% if issues %}
                {% for issue in issues %}<div class="issue">{{ issue }}</div>{% endfor %}
            {% else %}
                No major issues found.
            {% endif %}
        </div>
    </div>
    {% endif %}
</body>
</html>
"""

def is_valid_domain(domain):
    # Simple regex: domain.tld (no protocol, no path)
    pattern = r'^(?!\-)([A-Za-z0-9\-]{1,63}\.)+[A-Za-z]{2,}$'
    return re.match(pattern, domain) is not None

def run_dns_checks(domain):
    results = {
        "A Record": [],
        "www A Record": [],
        "IPv6": [],
        "MX Records": [],
        "NS Records": [],
        "TXT Records": []
    }
    try:
        for rdata in dns.resolver.resolve(domain, "A"): results["A Record"].append(rdata.to_text())
    except: pass
    try:
        for rdata in dns.resolver.resolve("www." + domain, "A"): results["www A Record"].append(rdata.to_text())
    except: pass
    try:
        for rdata in dns.resolver.resolve(domain, "AAAA"): results["IPv6"].append(rdata.to_text())
    except: results["IPv6"].append("No IPv6 Found")
    try:
        for rdata in dns.resolver.resolve(domain, "MX"): results["MX Records"].append(rdata.exchange.to_text())
    except: pass
    try:
        for rdata in dns.resolver.resolve(domain, "NS"): results["NS Records"].append(rdata.to_text())
    except: pass
    try:
        for rdata in dns.resolver.resolve(domain, "TXT"): results["TXT Records"].append(rdata.to_text().strip('"'))
    except: pass
    return results

def run_whois(domain):
    try:
        w = whois.whois(domain)
        return w
    except:
        return None

def run_curl(domain):
    try:
        output = subprocess.check_output(["curl", "-I", f"http://{domain}"], stderr=subprocess.STDOUT, timeout=5).decode("utf-8")
        return output
    except:
        return "Curl request failed."

def check_missing_headers(curl_output):
    headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"]
    missing = []
    for h in headers:
        if h.lower() not in curl_output.lower():
            missing.append(h)
    return missing

@app.route("/", methods=["GET", "POST"])
def index():
    domain = request.form.get("domain", "").strip()
    error, dns_results, whois_data, whois_ns, curl_output, missing_headers, issues = None, {}, None, [], "", [], []

    if request.method == "POST":
        if not is_valid_domain(domain):
            error = "Invalid input. Please enter a valid domain name (example.com)"
        else:
            dns_results = run_dns_checks(domain)
            whois_data = run_whois(domain)
            if whois_data and whois_data.name_servers:
                whois_ns = sorted(whois_data.name_servers)
            curl_output = run_curl(domain)
            missing_headers = check_missing_headers(curl_output)

            # Collect issues (only if missing)
            if not dns_results["A Record"]: issues.append("Missing A Record")
            if not dns_results["www A Record"]: issues.append("Missing www A Record")
            if "No IPv6 Found" in dns_results["IPv6"]: issues.append("Missing IPv6")
            if not dns_results["MX Records"]: issues.append("Missing MX Records")
            if not dns_results["NS Records"]: issues.append("Missing NS Records")
            if not dns_results["TXT Records"]: issues.append("Missing TXT Records")
            if missing_headers:
                issues.append("Missing Security Headers: " + ", ".join(missing_headers))

    return render_template_string(TEMPLATE, domain=domain, error=error, dns_results=dns_results, whois_data=whois_data,
                                  whois_ns=whois_ns, curl_output=curl_output, missing_headers=missing_headers, issues=issues)

if __name__ == "__main__":
    app.run(debug=True)
