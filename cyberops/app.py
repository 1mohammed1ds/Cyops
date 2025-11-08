import json
import os
import sqlite3
import hashlib
import uuid
from datetime import datetime
from typing import Dict, Optional, Tuple

import numpy as np
import pandas as pd
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from sklearn.linear_model import LogisticRegression
import tldextract


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed")
DB_PATH = os.path.join(BASE_DIR, "cyberops.db")


app = Flask(__name__)
app.secret_key = os.getenv("CYBEROPS_SECRET", "dev-secret")
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["PROCESSED_FOLDER"] = PROCESSED_DIR
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB
app.config["ENFORCE_HTTPS"] = os.getenv("ENFORCE_HTTPS", "0").lower() in {"1", "true", "yes"}
app.config["SESSION_COOKIE_SECURE"] = app.config["ENFORCE_HTTPS"]
app.config["PREFERRED_URL_SCHEME"] = "https" if app.config["ENFORCE_HTTPS"] else "http"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def log_activity(module: str, details: Dict) -> None:
    info = json.dumps(details)[:2000]
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO activity_logs (module, details, created_at) VALUES (?, ?, ?)",
            (module, info, datetime.utcnow().isoformat()),
        )
        conn.commit()


class LogAnomalyScorer:
    def __init__(self) -> None:
        ratios = np.linspace(0, 1, 11)
        severities = [0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1]
        df = pd.DataFrame({"ratio": ratios, "label": severities})
        self.model = LogisticRegression(solver="liblinear")
        self.model.fit(df[["ratio"]], df["label"])

    def score(self, ratio: float) -> Tuple[str, float]:
        ratio = max(0.0, min(1.0, ratio))
        prob = float(self.model.predict_proba([[ratio]])[0][1])
        if prob >= 0.75:
            label = "critical"
        elif prob >= 0.4:
            label = "warning"
        else:
            label = "safe"
        return label, prob


class PhishingDetector:
    def __init__(self) -> None:
        data = pd.DataFrame(
            [
                # url_len, num_dots, num_hyphen, has_https, has_suspicious_word, label
                [20, 1, 0, 1, 0, 0],
                [55, 4, 2, 0, 1, 1],
                [12, 0, 0, 1, 0, 0],
                [75, 5, 3, 0, 1, 1],
                [40, 2, 1, 1, 0, 0],
                [90, 6, 2, 0, 1, 1],
                [30, 1, 0, 0, 1, 1],
                [65, 3, 1, 1, 1, 1],
                [18, 1, 0, 1, 0, 0],
                [48, 2, 1, 0, 1, 1],
            ],
            columns=["url_len", "dots", "hyphen", "https", "word", "label"],
        )
        self.model = LogisticRegression(solver="liblinear")
        self.model.fit(data[["url_len", "dots", "hyphen", "https", "word"]], data["label"])

    def extract_features(self, text: str) -> Tuple[np.ndarray, Dict[str, int]]:
        text = text.strip()
        ext = tldextract.extract(text)
        domain = ".".join(filter(None, [ext.domain, ext.suffix])) if ext.suffix else ext.domain
        url_len = len(text)
        dots = text.count(".")
        hyphen = text.count("-")
        https = 1 if text.lower().startswith("https") else 0
        suspicious_words = {"verify", "login", "update", "urgent", "click"}
        word_flag = 1 if any(word in text.lower() for word in suspicious_words) else 0
        features = np.array([[url_len, dots, hyphen, https, word_flag]])
        breakdown = {
            "domain": domain or "(n/a)",
            "url_len": url_len,
            "dots": dots,
            "hyphen": hyphen,
            "https": https,
            "suspicious_words": word_flag,
        }
        return features, breakdown

    def classify(self, text: str) -> Tuple[str, float, Dict[str, int]]:
        features, breakdown = self.extract_features(text)
        prob = float(self.model.predict_proba(features)[0][1])
        if prob >= 0.75:
            label = "malicious"
        elif prob >= 0.45:
            label = "suspicious"
        else:
            label = "safe"
        return label, prob, breakdown


log_scorer = LogAnomalyScorer()
phishing_detector = PhishingDetector()


ALLOWED_LOG_EXT = {"txt", "log"}


def allowed_log_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_LOG_EXT


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=150_000,
    )
    return kdf.derive(password.encode("utf-8"))


@app.before_request
def enforce_https():
    if not app.config["ENFORCE_HTTPS"]:
        return None
    if request.is_secure:
        return None
    if request.headers.get("X-Forwarded-Proto", "http") == "https":
        return None
    url = request.url.replace("http://", "https://", 1)
    return redirect(url, code=301)


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net",
    )
    return response


@app.route("/")
def index():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        recent = conn.execute(
            "SELECT module, created_at FROM activity_logs ORDER BY created_at DESC LIMIT 5"
        ).fetchall()
        totals = conn.execute(
            "SELECT module, COUNT(*) as count FROM activity_logs GROUP BY module"
        ).fetchall()
    stats = {row["module"]: row["count"] for row in totals}
    return render_template("index.html", active_tab="home", recent=recent, stats=stats)


@app.route("/logs", methods=["GET", "POST"])
def logs():
    if request.method == "GET":
        return render_template("logs.html", active_tab="logs", results=None)

    file = request.files.get("logfile")
    if file is None or file.filename == "":
        flash("Please choose a log file to upload.")
        return render_template("logs.html", active_tab="logs", results=None)

    if not allowed_log_file(file.filename):
        flash("Only .log and .txt files are supported.")
        return render_template("logs.html", active_tab="logs", results=None)

    filename = os.path.basename(file.filename)
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(save_path)

    keywords = ("fail", "error", "denied", "invalid", "unauthorized")
    suspicious_lines = []
    total_lines = 0
    suspicious_count = 0
    with open(save_path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            total_lines += 1
            lower = line.lower()
            if any(word in lower for word in keywords):
                suspicious_count += 1
                if len(suspicious_lines) < 10:
                    suspicious_lines.append(line.rstrip("\n"))

    ratio = (suspicious_count / total_lines) if total_lines else 0
    severity = "safe"
    if ratio >= 0.25:
        severity = "critical"
    elif ratio >= 0.1:
        severity = "warning"

    ml_label, ml_score = log_scorer.score(ratio)

    results = {
        "filename": filename,
        "total": total_lines,
        "suspicious": suspicious_count,
        "ratio": round(ratio * 100, 2),
        "severity": severity,
        "samples": suspicious_lines,
        "ml_label": ml_label,
        "ml_score": round(ml_score * 100, 1),
        "keywords": ", ".join(keywords),
    }
    log_activity("logs", {"filename": filename, "severity": severity, "ratio": ratio})
    return render_template("logs.html", active_tab="logs", results=results)


@app.route("/phishing", methods=["GET", "POST"])
def phishing():
    if request.method == "GET":
        return render_template("phishing.html", active_tab="phishing", result=None)

    text = request.form.get("indicator", "").strip()
    if not text:
        flash("Please enter a URL or email snippet to analyse.")
        return render_template("phishing.html", active_tab="phishing", result=None)

    label, score, breakdown = phishing_detector.classify(text)
    result = {
        "label": label,
        "score": round(score * 100, 1),
        "indicator": text,
        "features": breakdown,
    }
    log_activity("phishing", {"label": label, "score": score})
    return render_template("phishing.html", active_tab="phishing", result=result)


def sha256_of_file(file_storage, chunk: int = 8192) -> str:
    stream = file_storage.stream
    try:
        start = stream.tell()
    except Exception:
        start = None

    try:
        stream.seek(0)
    except Exception:
        pass

    digest = hashlib.sha256()
    while True:
        data = stream.read(chunk)
        if not data:
            break
        digest.update(data)
    hex_digest = digest.hexdigest()

    try:
        if start is not None:
            stream.seek(start)
        else:
            stream.seek(0)
    except Exception:
        pass
    return hex_digest


@app.route("/integrity", methods=["GET", "POST"])
def integrity():
    if request.method == "GET":
        return render_template("integrity.html", active_tab="integrity", result=None)

    file1 = request.files.get("file1")
    file2 = request.files.get("file2")
    if not file1 or not file1.filename or not file2 or not file2.filename:
        flash("Please upload both files.")
        return render_template("integrity.html", active_tab="integrity", result=None)

    sha1 = sha256_of_file(file1)
    sha2 = sha256_of_file(file2)
    match = sha1 == sha2
    result = {"sha1": sha1, "sha2": sha2, "match": match}
    log_activity("integrity", {"match": match})
    return render_template("integrity.html", active_tab="integrity", result=result)


def lookup_virustotal(indicator: str) -> Dict:
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"source": "VirusTotal", "demo": True, "indicator": indicator, "malicious": 0, "suspicious": 0}

    cleaned = indicator.strip()
    if is_ip(cleaned):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{cleaned}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{cleaned}"

    try:
        response = requests.get(url, headers={"x-apikey": api_key}, timeout=15)
    except requests.RequestException as exc:
        return {"source": "VirusTotal", "error": f"Request failed: {exc}"}
    if not response.ok:
        return {"source": "VirusTotal", "error": f"HTTP {response.status_code}"}
    data = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "source": "VirusTotal",
        "malicious": data.get("malicious", 0),
        "suspicious": data.get("suspicious", 0),
        "harmless": data.get("harmless", 0),
    }


def lookup_abuseipdb(indicator: str) -> Dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key or not is_ip(indicator):
        return {"source": "AbuseIPDB", "demo": True, "abuseConfidenceScore": 0}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": indicator, "maxAgeInDays": 90}
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
    except requests.RequestException as exc:
        return {"source": "AbuseIPDB", "error": f"Request failed: {exc}"}
    if not response.ok:
        return {"source": "AbuseIPDB", "error": f"HTTP {response.status_code}"}
    data = response.json().get("data", {})
    return {"source": "AbuseIPDB", "abuseConfidenceScore": data.get("abuseConfidenceScore", 0)}


def lookup_shodan(indicator: str) -> Dict:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key or not is_ip(indicator):
        return {"source": "Shodan", "demo": True, "ports": []}
    url = f"https://api.shodan.io/shodan/host/{indicator}?key={api_key}"
    try:
        response = requests.get(url, timeout=15)
    except requests.RequestException as exc:
        return {"source": "Shodan", "error": f"Request failed: {exc}"}
    if not response.ok:
        return {"source": "Shodan", "error": f"HTTP {response.status_code}"}
    data = response.json()
    return {"source": "Shodan", "ports": data.get("ports", []), "hostnames": data.get("hostnames", [])}


def combine_reputation(results: Dict[str, Dict]) -> Dict:
    malicious = sum(item.get("malicious", 0) for item in results.values())
    suspicious = sum(item.get("suspicious", 0) for item in results.values())
    abuse_score = results["abuseipdb"].get("abuseConfidenceScore", 0)
    if malicious >= 5 or abuse_score >= 75:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 2 or abuse_score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"
    return {"verdict": verdict, "malicious": malicious, "suspicious": suspicious, "abuseScore": abuse_score}


def is_ip(value: str) -> bool:
    parts = value.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        number = int(part)
        if number < 0 or number > 255:
            return False
    return True


@app.route("/threatintel", methods=["GET", "POST"])
def threatintel():
    if request.method == "GET":
        return render_template("threatintel.html", active_tab="threat", result=None)

    indicator = request.form.get("indicator", "").strip()
    if not indicator:
        flash("Enter an IP address or domain to query.")
        return render_template("threatintel.html", active_tab="threat", result=None)

    vt = lookup_virustotal(indicator)
    abuse = lookup_abuseipdb(indicator)
    shodan = lookup_shodan(indicator)
    combined = combine_reputation({"virustotal": vt, "abuseipdb": abuse, "shodan": shodan})

    result = {"indicator": indicator, "combined": combined, "sources": [vt, abuse, shodan]}
    log_activity("threatintel", {"indicator": indicator, "verdict": combined["verdict"]})
    return render_template("threatintel.html", active_tab="threat", result=result)


def process_crypto(file_storage, password: str, mode: str) -> Tuple[bool, str, Optional[str]]:
    if not password:
        return False, "Password is required for encryption and decryption.", None

    filename = os.path.basename(file_storage.filename)
    data = file_storage.read()
    if mode == "encrypt":
        salt = os.urandom(16)
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        output = salt + nonce + ciphertext
        suffix = ".enc"
        message = "File encrypted successfully."
    else:
        if len(data) < 28:
            return False, "Encrypted data is too short or invalid.", None
        salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        try:
            output = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return False, "Failed to decrypt. Check the password or file.", None
        suffix = ".dec"
        message = "File decrypted successfully."

    unique_name = f"{uuid.uuid4().hex}_{filename}{suffix}"
    output_path = os.path.join(app.config["PROCESSED_FOLDER"], unique_name)
    with open(output_path, "wb") as handle:
        handle.write(output)
    return True, message, unique_name


@app.route("/crypto", methods=["GET", "POST"])
def crypto():
    if request.method == "GET":
        return render_template("crypto.html", active_tab="crypto", result=None)

    file = request.files.get("file")
    password = request.form.get("password", "").strip()
    mode = request.form.get("mode", "encrypt")

    if not file or not file.filename:
        flash("Please upload a file to process.")
        return render_template("crypto.html", active_tab="crypto", result=None)

    success, message, stored_filename = process_crypto(file, password, mode)
    if not success:
        flash(message)
        return render_template("crypto.html", active_tab="crypto", result=None)

    result = {"message": message, "download": url_for("download_processed", filename=stored_filename)}
    log_activity("crypto", {"mode": mode})
    return render_template("crypto.html", active_tab="crypto", result=result)


@app.route("/downloads/<path:filename>")
def download_processed(filename: str):
    return send_from_directory(app.config["PROCESSED_FOLDER"], filename, as_attachment=True)


init_db()


if __name__ == "__main__":
    app.run(debug=True)
