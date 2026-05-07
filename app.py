from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import urllib.parse
from datetime import datetime
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_dev_key')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_DURATION'] = 86400
app.config['SESSION_PERMANENT'] = True

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class ScanRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, nullable=False)
    client_username = db.Column(db.String(150))
    target = db.Column(db.String(300))
    template = db.Column(db.String(200))
    priority = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default="Pending")
    completed_at = db.Column(db.DateTime, nullable=True)

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, nullable=False)
    target = db.Column(db.String(300))
    issue = db.Column(db.String(300))
    severity = db.Column(db.String(50))
    description = db.Column(db.Text)
    source = db.Column(db.String(500), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/")
def home():
    return render_template("Home-1.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/methodology")
def methodology():
    return render_template("methodology.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        if current_user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("client_dashboard"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):

            if user.role == "admin":

                session['pending_admin_id'] = str(user.id)
                session.modified = True
                return redirect(url_for("verify_2fa"))

            elif user.role == "client":

                login_user(user, remember=True)
                return redirect(url_for("client_dashboard"))

        flash('Invalid credentials', 'error')
    return render_template("login.html")

@app.route("/login/2fa", methods=["GET", "POST"])
def verify_2fa():

    if 'pending_admin_id' not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        code = request.form.get("2fa_code", "").strip()

        if len(code) == 5 and code.isdigit():

            user_id = session.get('pending_admin_id')
            user = db.session.get(User, int(user_id))

            if user:
                login_user(user, remember=True)

                session.pop('pending_admin_id', None)
                return redirect(url_for("admin_dashboard"))

        else:
            flash('Invalid format. Please enter a 5-digit code.', 'error')

    return render_template("2fa_page.html")

@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        return redirect(url_for('login'))

    requests = ScanRequest.query.order_by(ScanRequest.id.desc()).all()
    total_scans = ScanRequest.query.filter_by(status="Completed").count()
    findings_detected = Finding.query.count()
    active_clients = db.session.query(ScanRequest.client_id).filter_by(status="Pending").distinct().count()
    recent_findings = Finding.query.order_by(Finding.id.desc()).all()

    chart_critical = Finding.query.filter_by(severity="Critical").count()
    chart_high     = Finding.query.filter_by(severity="High").count()
    chart_medium   = Finding.query.filter_by(severity="Medium").count()
    chart_low      = Finding.query.filter_by(severity="Low").count()

    return render_template(
        "admin.html",
        requests=requests,
        total_scans=total_scans,
        findings_detected=findings_detected,
        active_clients=active_clients,
        recent_findings=recent_findings,
        chart_critical=chart_critical,
        chart_high=chart_high,
        chart_medium=chart_medium,
        chart_low=chart_low
    )

def get_cve_details(issue_name, cve_map):
    issue_lower = issue_name.lower()
    for key, data in cve_map.items():
        if key.lower() in issue_lower:
            return data
        for alias in data.get("aliases", []):
            if alias.lower() in issue_lower:
                return data
    return None

def is_safe_to_scan(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        domain = urllib.parse.urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]

        unsafe_keywords = ["localhost", "127.0.0.1", "0.0.0.0", "internal", "192.168.", "10.0."]
        if any(key in domain for key in unsafe_keywords):
            return False, "Your scan request has NOT been sent to admin as it is not a E-commerce platform."

        forbidden_tlds = [".gov", ".edu", ".mil", ".int"]
        if any(domain.endswith(tld) for tld in forbidden_tlds):
            return False, "Your scan request has NOT been sent to admin as it is not a E-commerce platform."

        forbidden_domains = [

            "google.com", "facebook.com", "apple.com", "amazon.com", "microsoft.com",
            "yahoo.com", "bing.com", "duckduckgo.com", "yandex.com", "ebay.com",

            "twitter.com", "x.com", "instagram.com", "linkedin.com", "tiktok.com",
            "pinterest.com", "snapchat.com", "reddit.com", "tumblr.com", "threads.net",

            "aws.amazon.com", "azure.com", "cloud.google.com", "cloudflare.com",
            "digitalocean.com", "heroku.com", "vercel.app", "netlify.com",
            "fastly.com", "linode.com", "akamai.com", "supabase.com",

            "github.com", "gitlab.com", "bitbucket.org", "atlassian.com",
            "jira.com", "confluence.com", "docker.com", "npm.com", "pypi.org",

            "netflix.com", "youtube.com", "twitch.tv", "hulu.com", "disneyplus.com",
            "spotify.com", "vimeo.com", "soundcloud.com",

            "stripe.com", "paypal.com", "square.com", "adyen.com", "braintree.com",
            "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "capitalone.com",
            "visa.com", "mastercard.com", "americanexpress.com",

            "hackerone.com", "bugcrowd.com",

            "slack.com", "zoom.us", "salesforce.com", "hubspot.com", "notion.so",
            "mailchimp.com", "dropbox.com", "zoom.com", "webex.com"
        ]

        if any(domain == fd or domain.endswith("." + fd) for fd in forbidden_domains):
            return False, "Your scan request has NOT been sent to admin as it is not a E-commerce platform."

        return True, "Safe"
    except Exception:
        return False, "Invalid URL format."

@app.route("/run_scan/<int:req_id>")
@login_required
def run_scan(req_id):
    if current_user.role != "admin":
        return redirect(url_for('login'))

    req = db.session.get(ScanRequest, req_id)
    clean_target = req.target.replace("https://", "").replace("http://", "")

    req.status = "Scan In Progress"
    db.session.commit()

    findings_list = []
    import subprocess
    import json
    import requests

    try:
        with open("cve_data.json", "r") as f:
            cve_map = json.load(f)
    except:
        cve_map = {}

    template = req.template.lower()
    ecomm_templates = ["payment & checkout", "customer data", "admin panel", "cart & api"]
    is_ecommerce_scan = any(t in template for t in ecomm_templates)

    headers_config = {
        "User-Agent": "Mozilla/5.0 (MisconfigLab Scanner)"
    }

    url = clean_target
    if not url.startswith("http"):
        url = "http://" + url

    if not is_ecommerce_scan:
        try:
            result = subprocess.check_output(
                ["nmap", "-sV", clean_target],
                universal_newlines=True
            )
            for line in result.split("\n"):
                if "/tcp" in line and "open" in line:
                    service_info = line.strip()
                    service_lower = service_info.lower()
                    issue = "Open Port Detected"
                    severity = "Low"
                    description = f"Service exposed: {service_info}"

                    for key, data in cve_map.items():
                        if key.lower() in service_lower:
                            issue = f"{data['issue']} ({data.get('cve','')})"
                            severity = data.get("severity", "Low")
                            description = data.get("desc", "")
                            break
                    findings_list.append((issue, severity, description, clean_target))
        except Exception as e:
            findings_list.append(("Scan Error", "Low", str(e), clean_target))

        try:
            r = requests.get(url, timeout=10, verify=False, headers=headers_config)
            html = r.text.lower()
            headers = str(r.headers).lower()

            security_headers = [
                "x-frame-options",
                "content-security-policy",
                "x-content-type-options",
                "strict-transport-security"
            ]

            for header in security_headers:
                if header not in headers:
                    issue_name = f"Missing Security Header: {header}"
                    data = get_cve_details(issue_name, cve_map)
                    if data:
                        findings_list.append((data["issue"], data.get("severity", "Medium"), data.get("desc", ""), url))
                    else:
                        findings_list.append((issue_name, "Medium", f"{header} header is not set.", url))

            if "server" in headers:
                issue_name = "Server Version Exposure"
                data = get_cve_details(issue_name, cve_map)
                if data:
                    findings_list.append((data["issue"], data.get("severity", "Low"), data.get("desc", ""), url))
                else:
                    findings_list.append((issue_name, "Low", "Server header reveals stack.", url))

            if any(x in html for x in ["debug", "stack trace", "exception"]):
                findings_list.append(("Debug Information Exposure", "High", "Application may be in debug mode.", url))

        except requests.exceptions.ConnectTimeout:
            findings_list.append(("Connection Timeout", "Low", "Target too slow or blocking", url))
        except requests.exceptions.ConnectionError:
            findings_list.append(("Connection Failed", "Medium", "Target unreachable", url))
        except Exception as e:
            findings_list.append(("Web Scan Error", "Low", str(e), url))

        try:

            common_paths = [
                "/admin", "/login", "/dashboard",
                "/.env", "/.git", "/backup",
                "/api", "/server-status",
                "/ftp"
            ]
            for path in common_paths:
                full_url = url.rstrip("/") + path
                try:
                    res = requests.get(full_url, timeout=5, verify=False, headers=headers_config)
                    if res.status_code == 200:
                        def add_finding(issue_name, default_severity, default_desc):
                            data = get_cve_details(issue_name, cve_map)
                            if data:
                                findings_list.append((data["issue"], data.get("severity", default_severity), data.get("desc", default_desc), full_url))
                            else:
                                findings_list.append((issue_name, default_severity, default_desc, full_url))

                        if ".env" in path:
                            add_finding("Exposed .env File", "Critical", "Environment file exposed.")
                        elif ".git" in path:
                            add_finding("Exposed Git Repo", "Critical", "Git repository exposed.")
                        elif "admin" in path:
                            add_finding("Admin Panel Found", "Medium", "Admin panel is accessible.")
                        elif "api" in path:
                            add_finding("Public API Found", "Medium", "API endpoint discovered.")

                        if "index of /" in res.text.lower():
                            add_finding("Directory Listing Enabled", "High", "Directory indexing is turned on.")
                except:
                    continue
        except Exception as e:
            findings_list.append(("Endpoint Scan Error", "Low", str(e), url))

    else:

        if "payment & checkout" in template:
            checkout_paths = [
                "/checkout", "/payment", "/cart/checkout",
                "/order/payment", "/pay", "/billing"
            ]
            for path in checkout_paths:
                full_url = url.rstrip("/") + path
                try:
                    res = requests.get(full_url, timeout=5, verify=False, headers=headers_config)
                    if res.status_code == 200:
                        if full_url.startswith("http://"):
                            findings_list.append((
                                "Checkout Served Over HTTP (PCI DSS Req 4.2.1)",
                                "Critical",
                                "PCI DSS Requirement 4.2.1 mandates strong cryptography for all "
                                "cardholder data in transit. Serving checkout over HTTP exposes "
                                "card numbers, CVVs, and billing details to network interception.",
                                full_url
                            ))

                        res_headers = str(res.headers).lower()
                        if "content-security-policy" not in res_headers:
                            findings_list.append((
                                "Payment Page Missing CSP (PCI DSS Req 6.4.1)",
                                "Critical",
                                "PCI DSS Requirement 6.4.1 requires a CSP on all payment pages "
                                "to prevent Magecart-style card-skimming script injection.",
                                full_url
                            ))
                        if "strict-transport-security" not in res_headers:
                            findings_list.append((
                                "HSTS Missing on Payment Page (PCI DSS Req 6.3.3)",
                                "High",
                                "Without HSTS, browsers may allow downgrade attacks to HTTP on "
                                "payment pages, violating PCI DSS secure transmission requirements.",
                                full_url
                            ))
                        if "x-frame-options" not in res_headers:
                            findings_list.append((
                                "Clickjacking Risk on Payment Page (PCI DSS Req 6.4.2)",
                                "High",
                                "Payment forms without frame protection are vulnerable to "
                                "clickjacking attacks that trick users into submitting card data "
                                "to attacker-controlled overlays.",
                                full_url
                            ))
                except:
                    continue

        elif "customer data" in template:

            sensitive_paths = [
                "/api/customers", "/api/orders", "/api/users",
                "/api/accounts", "/api/profiles", "/customers",
                "/users/export", "/orders/export",
                "/rest/user/login", "/api/Users"
            ]
            for path in sensitive_paths:
                full_url = url.rstrip("/") + path
                try:
                    res = requests.get(full_url, timeout=5, verify=False, headers=headers_config)
                    if res.status_code == 200:
                        findings_list.append((
                            "Unauthenticated Customer Data Endpoint (PCI DSS Req 7.1)",
                            "Critical",
                            "PCI DSS Requirement 7.1 mandates that access to cardholder and "
                            "customer data is restricted to authorised personnel only. "
                            "Unauthenticated access to customer records constitutes a data breach risk.",
                            full_url
                        ))

                        res_text = res.text.lower()
                        if any(kw in res_text for kw in ["email", "phone", "address", "card", "pan"]):
                            findings_list.append((
                                "PII Exposed in API Response (PCI DSS Req 3.3)",
                                "Critical",
                                "PCI DSS Requirement 3.3 prohibits storage "
                                "and exposure of sensitive authentication data after authorisation. "
                                "Ensure all customer data endpoints require authentication and return "
                                "only masked or tokenised values.",
                                full_url
                            ))
                    elif res.status_code == 403:
                        res_headers = str(res.headers).lower()
                        if "www-authenticate" not in res_headers:
                            findings_list.append((
                                "Weak Access Control on Customer Endpoint (PCI DSS Req 7.2)",
                                "Medium",
                                "PCI DSS Requirement 7.2 requires a formal access control system. "
                                "HTTP 403 without proper auth challenge may indicate misconfigured "
                                "ACLs that could be bypassed with header manipulation.",
                                full_url
                            ))
                except:
                    continue

        elif "admin panel" in template:
            admin_paths = [
                "/admin", "/admin/login", "/wp-admin",
                "/administrator", "/dashboard", "/manage",
                "/admin/users", "/admin/orders", "/admin/settings",
                "/backend", "/cms", "/cp"
            ]
            for path in admin_paths:
                full_url = url.rstrip("/") + path
                try:
                    res = requests.get(full_url, timeout=5, verify=False, headers=headers_config)
                    res_headers = str(res.headers).lower()
                    if res.status_code == 200:
                        findings_list.append((
                            "Admin Panel Publicly Accessible (PCI DSS Req 7.2)",
                            "Critical",
                            "PCI DSS Requirement 7.2 requires that access to system components "
                            "is denied by default and granted only to authorised individuals. "
                            "Publicly exposed admin panels are a primary target for credential "
                            "stuffing and brute-force attacks.",
                            full_url
                        ))
                        if "mfa" not in res.text.lower() and "two-factor" not in res.text.lower() and "2fa" not in res.text.lower():
                            findings_list.append((
                                "No MFA Evidence on Admin Login (PCI DSS Req 8.4)",
                                "High",
                                "PCI DSS Requirement 8.4 mandates MFA for all "
                                "non-console administrative access into the cardholder data environment. "
                                "Single-factor admin access significantly increases account takeover risk.",
                                full_url
                            ))
                        if "strict-transport-security" not in res_headers:
                            findings_list.append((
                                "Admin Panel Missing HSTS (PCI DSS Req 6.3.3)",
                                "High",
                                "Admin interfaces without HSTS can be accessed over HTTP via "
                                "downgrade attacks, exposing admin credentials in plaintext. "
                                "PCI DSS requires all administrative interfaces to enforce HTTPS.",
                                full_url
                            ))
                except:
                    continue

        elif "cart & api" in template:
            cart_api_paths = [
                "/cart", "/api/cart", "/checkout/api",
                "/api/products", "/api/pricing", "/api/discount",
                "/api/vouchers", "/api/inventory"
            ]
            for path in cart_api_paths:
                full_url = url.rstrip("/") + path
                try:
                    res = requests.get(full_url, timeout=5, verify=False, headers=headers_config)
                    res_headers = str(res.headers).lower()

                    if res.status_code == 200:
                        if "rate-limit" not in res_headers and "x-ratelimit" not in res_headers:
                            findings_list.append((
                                "Cart / API Missing Rate Limiting (PCI DSS Req 6.2.4)",
                                "High",
                                "PCI DSS Requirement 6.2.4 requires protections against automated "
                                "attacks. Without rate limiting, cart and pricing APIs are vulnerable "
                                "to enumeration, price manipulation, and credential stuffing attacks.",
                                full_url
                            ))

                        if "access-control-allow-origin" in res_headers:
                            if "access-control-allow-origin: *" in res_headers:
                                findings_list.append((
                                    "Cart API Allows All CORS Origins (PCI DSS Req 6.2.4)",
                                    "High",
                                    "A wildcard CORS policy allows any external website to make "
                                    "authenticated requests on behalf of a logged-in user. "
                                    "For cart and payment APIs, CORS must be restricted to "
                                    "trusted origins only per PCI DSS secure coding requirements.",
                                    full_url
                                ))

                        res_text = res.text.lower()
                        if any(kw in res_text for kw in ["card", "pan", "cvv", "expiry", "token"]):
                            findings_list.append((
                                "Payment Data Exposed in Cart API Response (PCI DSS Req 3.3)",
                                "Critical",
                                "PCI DSS Requirement 3.3 prohibits exposure of sensitive authentication "
                                "data. Cart and order APIs must never return raw PANs, CVVs, or "
                                "unencrypted payment tokens in API responses.",
                                full_url
                            ))
                except:
                    continue

    seen_issues = set()
    with db.session.no_autoflush:
        for issue, severity, description_text, source_text in findings_list:
            if issue in seen_issues:
                continue
            seen_issues.add(issue)

            existing = Finding.query.filter_by(
                request_id=req.id,
                issue=issue,
                target=clean_target
            ).first()

            if not existing:
                db.session.add(Finding(
                    request_id=req.id,
                    target=clean_target,
                    issue=issue,
                    severity=severity,
                    description=description_text,
                    source=source_text
                ))

    req.status = "Completed"
    req.completed_at = datetime.now()

    db.session.commit()
    flash("Scan completed successfully!", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/findings")
@login_required
def all_findings():
    if current_user.role != "admin":
        return redirect(url_for('login'))

    all_findings = Finding.query.order_by(Finding.id.desc()).all()
    critical = len([f for f in all_findings if f.severity == "Critical"])
    high     = len([f for f in all_findings if f.severity == "High"])
    medium   = len([f for f in all_findings if f.severity == "Medium"])
    low      = len([f for f in all_findings if f.severity == "Low"])

    risk_score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)
    return render_template("findings.html", findings=all_findings, risk_score=risk_score)

@app.route("/findings/<int:req_id>")
@login_required
def view_findings(req_id):
    if current_user.role != "admin":
        return redirect(url_for('login'))

    req = db.session.get(ScanRequest, req_id)
    findings = Finding.query.filter_by(request_id=req_id).all()

    critical = len([f for f in findings if f.severity == "Critical"])
    high = len([f for f in findings if f.severity == "High"])
    medium = len([f for f in findings if f.severity == "Medium"])
    low = len([f for f in findings if f.severity == "Low"])

    risk_score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)

    return render_template(
        "findings.html",
        findings=findings,
        risk_score=risk_score,
        req=req
    )

@app.route("/reports/<int:req_id>")
@login_required
def generate_report(req_id):
    if current_user.role != "admin":
        return redirect(url_for('login'))

    findings = Finding.query.filter_by(request_id=req_id).all()

    critical = len([f for f in findings if f.severity == "Critical"])
    high = len([f for f in findings if f.severity == "High"])
    medium = len([f for f in findings if f.severity == "Medium"])
    low = len([f for f in findings if f.severity == "Low"])

    risk_score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)

    return render_template(
        "report.html",
        findings=findings,
        risk_score=risk_score,
        critical=critical,
        high=high,
        medium=medium,
        low=low
    )

@app.route("/client/findings/<int:req_id>")
@login_required
def client_view_findings(req_id):
    if current_user.role != "client":
        return redirect(url_for('login'))

    req = db.session.get(ScanRequest, req_id)
    if not req or req.client_id != current_user.id:
        flash("Access denied.", "error")
        return redirect(url_for('client_dashboard'))

    findings = Finding.query.filter_by(request_id=req_id).all()
    critical = len([f for f in findings if f.severity == "Critical"])
    high     = len([f for f in findings if f.severity == "High"])
    medium   = len([f for f in findings if f.severity == "Medium"])
    low      = len([f for f in findings if f.severity == "Low"])

    risk_score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)

    return render_template("findings.html", findings=findings, risk_score=risk_score)

@app.route("/client/reports/<int:req_id>")
@login_required
def client_view_report(req_id):
    if current_user.role != "client":
        return redirect(url_for('login'))

    req = db.session.get(ScanRequest, req_id)
    if not req or req.client_id != current_user.id:
        flash("Access denied.", "error")
        return redirect(url_for('client_dashboard'))

    findings = Finding.query.filter_by(request_id=req_id).all()
    critical = len([f for f in findings if f.severity == "Critical"])
    high     = len([f for f in findings if f.severity == "High"])
    medium   = len([f for f in findings if f.severity == "Medium"])
    low      = len([f for f in findings if f.severity == "Low"])

    risk_score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)

    return render_template(
        "report.html",
        findings=findings,
        risk_score=risk_score,
        critical=critical,
        high=high,
        medium=medium,
        low=low
    )

@app.route("/client/findings")
@login_required
def client_all_findings():
    if current_user.role != "client":
        return redirect(url_for('login'))

    completed_requests = ScanRequest.query.filter_by(
        client_id=current_user.id,
        status="Completed"
    ).order_by(ScanRequest.id.desc()).all()

    all_findings = []
    for req in completed_requests:
        findings = Finding.query.filter_by(request_id=req.id).all()
        all_findings.extend(findings)

    critical = len([f for f in all_findings if f.severity == "Critical"])
    high     = len([f for f in all_findings if f.severity == "High"])
    medium   = len([f for f in all_findings if f.severity == "Medium"])
    low      = len([f for f in all_findings if f.severity == "Low"])

    risk_score = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)

    return render_template(
        "findings.html",
        findings=all_findings,
        risk_score=risk_score,
        req=None
    )

@app.route("/client/reports")
@login_required
def client_all_reports():
    if current_user.role != "client":
        return redirect(url_for('login'))

    completed_requests = ScanRequest.query.filter_by(
        client_id=current_user.id,
        status="Completed"
    ).order_by(ScanRequest.id.desc()).all()

    return render_template("client_reports.html", requests=completed_requests)

@app.route("/delete_all_findings")
@login_required
def delete_all_findings():
    if current_user.role != "admin":
        return redirect(url_for('login'))

    Finding.query.delete()
    db.session.commit()
    flash("All findings removed!", "success")
    return redirect(request.referrer or url_for("admin_dashboard"))

@app.route("/delete_selected_findings", methods=["POST"])
@login_required
def delete_selected_findings():
    if current_user.role != "admin":
        return redirect(url_for('login'))

    selected_ids = request.form.getlist("selected_findings")

    if selected_ids:
        for fid in selected_ids:
            finding = db.session.get(Finding, int(fid))
            if finding:
                db.session.delete(finding)

        db.session.commit()
        flash("Selected findings deleted!", "success")
    else:
        flash("No findings selected", "warning")

    return redirect(request.referrer or url_for("admin_dashboard"))

@app.route("/delete_request/<int:req_id>")
@login_required
def delete_request(req_id):
    if current_user.role != "admin":
        return redirect(url_for('login'))

    req = db.session.get(ScanRequest, req_id)

    if req:
        db.session.delete(req)
        db.session.commit()
        flash("Scan request deleted!", "success")

    return redirect(url_for("admin_dashboard"))

@app.route("/client/scan-status")
@login_required
def client_scan_status():
    from flask import jsonify
    if current_user.role != "client":
        return jsonify([])

    requests_data = ScanRequest.query.filter_by(
        client_id=current_user.id
    ).order_by(ScanRequest.id.desc()).all()

    return jsonify([{
        "id": r.id,
        "status": r.status,
        "target": r.target
    } for r in requests_data])

@app.route("/clients")
@login_required
def clients():
    if current_user.role != "admin":
        return redirect(url_for('login'))

    all_requests = ScanRequest.query.order_by(ScanRequest.id.desc()).all()
    return render_template("clients.html", requests=all_requests)

@app.route("/client/status")
@login_required
def client_status():
    from flask import jsonify
    if current_user.role != "client":
        return jsonify({"error": "unauthorized"}), 403

    requests = ScanRequest.query.filter_by(
        client_id=current_user.id
    ).all()

    return jsonify({
        "requests": [
            {"id": r.id, "status": r.status}
            for r in requests
        ]
    })

@app.route("/client")
@login_required
def client_dashboard():
    if current_user.role != "client":
        return redirect(url_for('login'))

    requests = ScanRequest.query.filter_by(
        client_id=current_user.id
    ).order_by(ScanRequest.id.desc()).all()

    pending_count = ScanRequest.query.filter_by(
        client_id=current_user.id,
        status="Pending"
    ).count()

    completed_ids = [r.id for r in requests if r.status == "Completed"]
    all_findings = Finding.query.filter(Finding.request_id.in_(completed_ids)).all() if completed_ids else []

    chart_critical = len([f for f in all_findings if f.severity == "Critical"])
    chart_high     = len([f for f in all_findings if f.severity == "High"])
    chart_medium   = len([f for f in all_findings if f.severity == "Medium"])
    chart_low      = len([f for f in all_findings if f.severity == "Low"])

    return render_template(
        "client.html",
        requests=requests,
        pending_count=pending_count,
        chart_critical=chart_critical,
        chart_high=chart_high,
        chart_medium=chart_medium,
        chart_low=chart_low,
        recent_findings=all_findings
    )

@app.route("/request-scan", methods=["GET", "POST"])
@login_required
def request_scan():
    if current_user.role != "client":
        return redirect(url_for('login'))

    if request.method == "POST":
        target_url = request.form.get("target")

        is_safe, error_msg = is_safe_to_scan(target_url)
        if not is_safe:
            flash(error_msg, "error")
            return redirect(url_for("request_scan"))

        raw_priority = request.form.get("priority")

        if "High" in raw_priority:
            priority = "High"
        elif "Medium" in raw_priority:
            priority = "Medium"
        else:
            priority = "Low"

        new_request = ScanRequest(
            client_id=current_user.id,
            client_username=current_user.username,
            target=target_url,
            template=request.form.get("template"),
            priority=priority,
            description=request.form.get("description"),
            status="Pending"
        )

        db.session.add(new_request)
        db.session.commit()

        flash("Scan request submitted successfully!", "success")
        return redirect(url_for("request_scan"))

    return render_template("request_scan.html")

@app.route("/learning-center")
@login_required
def learning_center():
    return render_template("learning-center.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for("home"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)