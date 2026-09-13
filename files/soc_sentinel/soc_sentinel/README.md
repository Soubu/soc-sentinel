# SOC Sentinel
#### Video Demo: <URL HERE>
#### Description:

SOC Sentinel is a web-based triage console built for security operations
(SOC) analysts. It takes the repetitive, error-prone parts of first-line
alert triage — pulling indicators of compromise out of raw log text,
neutralizing them safely for tickets, and decoding obfuscated commands —
and turns them into a fast, reliable web tool with a saved history of past
analyses. I built this project because I work as a SOC analyst myself, and
every one of these features is something I do manually, multiple times a
day, using a scattered mix of regex one-liners, CyberChef tabs, and sticky
notes. I wanted a single, purpose-built tool that does all of it in one
place, and that I could actually keep using after the course ends.

## What it does

**Analyze (IOC extraction).** The core feature. An analyst pastes a raw
log line, phishing email, or alert into a text box, and the app extracts
every IPv4 address, domain, URL, email address, and file hash (MD5, SHA-1,
SHA-256) it can find, grouped and displayed clearly. This is the single
most repetitive task in triage — manually re-reading a wall of log text to
spot every IP and hash by eye is slow and easy to get wrong, especially
during a long shift. The extraction logic is built entirely with Python's
`re` module: each IOC type has its own regular expression, and hashes are
de-duplicated by length so a 64-character SHA-256 doesn't also get counted
as part of a shorter match.

**Defang / Refang.** Security teams never share a live, clickable link or
a raw malicious IP in a ticket or chat message, since it could get
accidentally clicked or trigger automated systems. The convention is to
"defang" it first — `http://` becomes `hxxp://`, and every `.` becomes
`[.]`. This tool converts text in both directions: defang for writing
reports safely, or refang to restore an IOC back to its real form when you
need to actually paste it into a lookup tool like VirusTotal.

**Base64 Decode.** Attackers frequently obfuscate malicious PowerShell
commands using Base64, specifically via PowerShell's `-EncodedCommand`
flag, which encodes text as UTF-16LE before Base64-encoding it. Most
generic Base64 decoders don't know to look for that encoding and just
produce garbled output. My decoder tries UTF-16LE first, falls back to
UTF-8, and if neither produces readable text, shows the raw bytes instead
of failing silently — so an analyst can quickly tell if a suspicious
string is a plain command, a UTF-16 PowerShell payload, or actual binary
data.

**History.** Every analysis a user runs is saved to a SQLite database,
tied to their account, with a timestamp and a short preview. This turns
the tool from a one-off calculator into something with a memory — useful
if you need to check what you found in an earlier alert without having to
re-paste the same block of text.

**Reference pages.** A static but genuinely useful common-ports table and
a MITRE ATT&CK Enterprise tactics list (all 14 tactics, in kill-chain
order, with their official IDs and one-line descriptions), for quick
lookup during an investigation without needing to leave the tool or search
externally.

## Design and technical choices

The app is built with **Flask**, using **SQLite** for persistence and
server-rendered **Jinja2 templates** rather than a JavaScript framework,
since the workflow here is fundamentally form-in, result-out — a full
client-side framework would add complexity without adding value. Passwords
are hashed with Werkzeug's `generate_password_hash` / `check_password_hash`
rather than stored in plain text, and every core route is protected by a
`login_required` decorator that redirects unauthenticated users to the
login page.

The visual design deliberately avoids a generic dashboard look. SOC teams
genuinely work in dark, low-glare environments (often during night shifts),
so the interface uses a near-black background with an amber accent color —
a deliberate nod to the phosphor-amber terminals historically used in
security and network operations centers, rather than an arbitrary color
choice. IOC data is displayed in a monospace typeface (IBM Plex Mono)
specifically so that visually similar characters in hashes and IP
addresses remain easy to tell apart, while UI labels use a separate sans
typeface (IBM Plex Sans) to keep data and interface chrome visually
distinct.

## File structure

- `app.py` — all Flask routes, the IOC extraction/defang/Base64 logic, and
  database access functions
- `schema.sql` — defines the `users` and `analyses` tables
- `templates/` — Jinja2 templates, one per page, extending a shared
  `layout.html` that provides the sidebar navigation
- `static/style.css` — the full stylesheet for the console/terminal
  aesthetic described above
- `requirements.txt` — Flask and Werkzeug, the only two dependencies

## Use of AI

I used Claude (Anthropic) as a coding assistant while building this
project — specifically for scaffolding the Flask route structure, drafting
the initial CSS, and reviewing my regular expressions for the IOC
extractors. All logic was tested and verified by me before inclusion, and
I understand and can explain every part of the codebase.

## Running it locally

```
pip install -r requirements.txt
python3 app.py
```

Then visit `http://127.0.0.1:5000` and register an account to get started.
