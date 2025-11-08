CyberOpsHub
===========

Overview
--------
CyberOpsHub is a Flask-based SOC dashboard that unifies log monitoring, phishing detection, file integrity verification, multi-source threat intelligence, and AES encryption tooling. It is designed as a portfolio-ready demo with optional API integrations and lightweight ML models.

Features
--------
- **Log Monitor** – Upload `.log`/`.txt` files, highlight suspicious lines, and view rule + ML anomaly scoring with severity colour-coding.
- **Phishing Detector** – Paste a URL or email snippet; tldextract-driven feature engineering with a scikit-learn model classifies safe / suspicious / malicious.
- **File Integrity Checker** – Compare two files via SHA-256 hashes to confirm tampering.
- **Threat Intelligence** – Aggregate VirusTotal, AbuseIPDB, and Shodan data (demo fallbacks when keys are absent) into a single verdict.
- **Encryption Tool** – Password-based AES-GCM encrypt/decrypt with downloadable artefacts.
- **SQLite Activity Log** – Tracks recent module usage for the dashboard overview.

Tech Stack
----------
- Backend: Python, Flask, SQLite3
- Frontend: Bootstrap 5, custom CSS
- Libraries: requests, pandas, scikit-learn, cryptography, tldextract
- Optional APIs: VirusTotal, AbuseIPDB, Shodan

Prerequisites
-------------
- Python 3.10+
- (Optional) API keys: `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`

Setup
-----
```bash
cd cyberops
python -m venv .venv
.venv\Scripts\activate        # Windows
# or source .venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
```

Environment (optional)
----------------------
```powershell
setx VT_API_KEY "YOUR_VT_KEY"
setx ABUSEIPDB_API_KEY "YOUR_ABUSE_KEY"
setx SHODAN_API_KEY "YOUR_SHODAN_KEY"
setx ENFORCE_HTTPS "1"   # enable HTTPS redirect + secure cookies in production
```
Restart the shell after using `setx`, or export the variables in your IDE/run configuration.

Run
---
```bash
python app.py
```
Then open http://127.0.0.1:5000. The app initialises `cyberops.db` for activity logging on first launch.

Testing the Modules
-------------------
1. **Logs** – Upload a sample containing words like “failed login”, “error”, “denied”; inspect severity + ML risk.
2. **Phishing** – Try `https://secure-login-update.com/account`. Observe feature breakdown and classification.
3. **Integrity** – Compare identical vs edited files to see match/mismatch alerts.
4. **Threat Intel** – Query `8.8.8.8`. Without API keys you’ll see demo data; with keys you’ll receive live stats.
5. **Crypto** – Encrypt a small file with a password, download the `.enc`, then decrypt using the same password.

Security Notes
--------------
- Upload limit: 50 MB per request.
- Optional HTTPS enforcement (`ENFORCE_HTTPS=1`) adds secure cookies and 301 redirects.
- Response headers include CSP, HSTS, X-Frame-Options, and X-Content-Type-Options.
- Password-derived AES-GCM uses PBKDF2 (150k iterations) with per-file salt + nonce.

Roadmap Ideas
-------------
- Persist tool outputs in SQLite for historical reporting and charts.
- Replace demo ML baselines with trained models from production datasets.
- Integrate AbuseIPDB/Shodan pagination + enrichment, plus queueing for batch indicators.
- Add role-based auth and audit logging for multi-user scenarios.
