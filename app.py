import os
import re
import base64
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel.db")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")) as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# IOC extraction engine
# ---------------------------------------------------------------------------

IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
URL_RE = re.compile(r'\bhttps?://[^\s\'"<>]+', re.IGNORECASE)
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
DOMAIN_NOISE = {"e.g.com", "example.com", "domain.com"}


def extract_iocs(text):
    sha256 = sorted(set(SHA256_RE.findall(text)))
    sha1 = sorted(set(SHA1_RE.findall(text)) - set(sha256))
    md5 = sorted(set(MD5_RE.findall(text)) - set(sha1) - set(sha256))
    emails = sorted(set(EMAIL_RE.findall(text)))
    email_domains = {e.split('@')[-1] for e in emails}
    raw_domains = set(DOMAIN_RE.findall(text))
    domains = sorted(d for d in raw_domains if d.lower() not in DOMAIN_NOISE and d not in email_domains)

    return {
        "ipv4": sorted(set(IPV4_RE.findall(text))),
        "urls": sorted(set(URL_RE.findall(text))),
        "domains": domains,
        "emails": emails,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
    }


def defang(text):
    text = text.replace("http://", "hxxp://").replace("https://", "hxxps://")
    text = text.replace(".", "[.]")
    text = text.replace("@", "[at]")
    return text


def refang(text):
    text = text.replace("hxxp://", "http://").replace("hxxps://", "https://")
    text = text.replace("[.]", ".")
    text = text.replace("[at]", "@")
    return text


def decode_base64(text):
    text = text.strip().strip('"').strip("'")
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded_bytes = base64.b64decode(padded)
        try:
            decoded = decoded_bytes.decode('utf-16-le')
            if decoded.isprintable() or '\n' in decoded:
                return decoded, "UTF-16LE (likely PowerShell -EncodedCommand)"
        except (UnicodeDecodeError, UnicodeError):
            pass
        try:
            decoded = decoded_bytes.decode('utf-8')
            if decoded.isprintable() or '\n' in decoded:
                return decoded, "UTF-8"
        except (UnicodeDecodeError, UnicodeError):
            pass
        return repr(decoded_bytes), "raw bytes (non-printable / binary)"
    except Exception:
        return None, None


COMMON_PORTS = [
    (20, "FTP (data)"), (21, "FTP (control)"), (22, "SSH"), (23, "Telnet"),
    (25, "SMTP"), (53, "DNS"), (67, "DHCP (server)"), (68, "DHCP (client)"),
    (80, "HTTP"), (110, "POP3"), (123, "NTP"), (135, "MS RPC"),
    (139, "NetBIOS"), (143, "IMAP"), (161, "SNMP"), (389, "LDAP"),
    (443, "HTTPS"), (445, "SMB"), (465, "SMTPS"), (514, "Syslog"),
    (587, "SMTP (submission)"), (636, "LDAPS"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (1521, "Oracle DB"), (3306, "MySQL"), (3389, "RDP"),
    (5432, "PostgreSQL"), (5900, "VNC"), (6379, "Redis"), (8080, "HTTP (alt)"),
    (8443, "HTTPS (alt)"), (9200, "Elasticsearch"), (27017, "MongoDB"),
]

MITRE_TACTICS = [
    ("TA0043", "Reconnaissance", "Gathering info to plan future operations (scanning, OSINT)"),
    ("TA0042", "Resource Development", "Establishing resources (infra, accounts, malware)"),
    ("TA0001", "Initial Access", "Getting into the network (phishing, exploit, valid accounts)"),
    ("TA0002", "Execution", "Running malicious code (scripting, scheduled tasks)"),
    ("TA0003", "Persistence", "Maintaining foothold (registry run keys, services)"),
    ("TA0004", "Privilege Escalation", "Gaining higher-level permissions"),
    ("TA0005", "Defense Evasion", "Avoiding detection (obfuscation, disabling tools)"),
    ("TA0006", "Credential Access", "Stealing credentials (dumping, keylogging)"),
    ("TA0007", "Discovery", "Learning about the environment (network, accounts)"),
    ("TA0008", "Lateral Movement", "Moving through the environment (RDP, pass-the-hash)"),
    ("TA0009", "Collection", "Gathering data of interest"),
    ("TA0011", "Command and Control", "Communicating with compromised systems (C2)"),
    ("TA0010", "Exfiltration", "Stealing data out of the network"),
    ("TA0040", "Impact", "Disrupting, destroying, or manipulating systems/data"),
]


# ---------------------------------------------------------------------------
# Routes: Auth
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")

        if not username or not password:
            flash("Username and password are required.")
            return render_template("register.html")
        if password != confirmation:
            flash("Passwords do not match.")
            return render_template("register.html")

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            db.close()
            flash("That username is already taken.")
            return render_template("register.html")

        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )
        db.commit()
        db.close()
        flash("Account created. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()

        if user is None or not check_password_hash(user["hash"], password):
            flash("Invalid username or password.")
            return render_template("login.html")

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Routes: Core app
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    results = None
    submitted_text = ""
    if request.method == "POST":
        submitted_text = request.form.get("log_text", "")
        results = extract_iocs(submitted_text)
        total_found = sum(len(v) for v in results.values())

        db = get_db()
        db.execute(
            "INSERT INTO analyses (user_id, raw_text, ioc_count, created_at) VALUES (?, ?, ?, ?)",
            (session["user_id"], submitted_text[:2000], total_found, datetime.utcnow().isoformat()),
        )
        db.commit()
        db.close()

    return render_template("index.html", results=results, submitted_text=submitted_text)


@app.route("/tools/defang", methods=["GET", "POST"])
@login_required
def defang_tool():
    output = None
    input_text = ""
    mode = "defang"
    if request.method == "POST":
        input_text = request.form.get("input_text", "")
        mode = request.form.get("mode", "defang")
        output = defang(input_text) if mode == "defang" else refang(input_text)
    return render_template("defang.html", output=output, input_text=input_text, mode=mode)


@app.route("/tools/base64", methods=["GET", "POST"])
@login_required
def base64_tool():
    decoded = None
    method = None
    input_text = ""
    if request.method == "POST":
        input_text = request.form.get("input_text", "")
        decoded, method = decode_base64(input_text)
    return render_template("base64.html", decoded=decoded, method=method, input_text=input_text)


@app.route("/reference/ports")
@login_required
def ports_reference():
    return render_template("ports.html", ports=COMMON_PORTS)


@app.route("/reference/mitre")
@login_required
def mitre_reference():
    return render_template("mitre.html", tactics=MITRE_TACTICS)


@app.route("/history")
@login_required
def history():
    db = get_db()
    rows = db.execute(
        "SELECT id, ioc_count, created_at, substr(raw_text, 1, 80) AS preview "
        "FROM analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
        (session["user_id"],),
    ).fetchall()
    db.close()
    return render_template("history.html", rows=rows)


if not os.path.exists(DB_PATH):
    init_db()

if __name__ == "__main__":
    app.run(debug=True)
