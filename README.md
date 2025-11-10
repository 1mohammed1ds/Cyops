# 🛡️ CyberOpsHub — AI-Integrated Security Operations Dashboard

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python\&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black?logo=flask)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple?logo=bootstrap)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Project%20Status-Active-brightgreen)

---

### Unified Cybersecurity Dashboard Built with Flask

**CyberOpsHub** is a full-stack **Security Operations Center (SOC)** dashboard that brings together multiple cybersecurity utilities—log monitoring, file integrity checking, and threat-intelligence lookups—into one streamlined, AI-ready interface.

It’s designed as a hands-on, real-world style project for cybersecurity students, analysts, and developers who want to experience how professional SOC tools like Splunk, Darktrace, or SOAR systems unify data and automate detection.

---

## Features

### 🧾 Log Monitor

Upload log files (e.g., system, authentication, or web server logs) and automatically flag suspicious entries such as failed logins, invalid credentials, or access denials.

### 🔐 File Integrity Checker

Compare two files and verify whether tampering or unauthorized changes occurred using SHA-256 hashing.

### 🌍 Threat Intelligence Lookup

Check the reputation of IPs or domains using the **VirusTotal API**, with a fallback “demo mode” when no API key is provided.

### 🤖 AI Analyst *(Coming Soon)*

An intelligent assistant designed to summarize log anomalies, correlate findings, and recommend mitigation steps in natural language.

---

## 🧰 Tech Stack

| Layer           | Tools / Libraries                  |
| --------------- | ---------------------------------- |
| **Backend**     | Python, Flask, hashlib, requests   |
| **Frontend**    | HTML5, CSS3, Bootstrap 5, Jinja2   |
| **APIs**        | VirusTotal (optional)              |
| **Development** | VS Code, Git, virtual environments |

---

## 🧩 Project Structure

```
cyberops/
├── app.py
├── requirements.txt
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── index.html
    ├── logs.html
    ├── integrity.html
    ├── threat.html
    └── ai.html
```

---

## ⚙️ Setup & Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/CyberOpsHub.git
cd CyberOpsHub
```

### 2. Create a virtual environment

```bash
python -m venv venv
.\venv\Scripts\activate        # Windows
# or
source venv/bin/activate       # macOS/Linux
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. (Optional) Add your VirusTotal API key

```bash
setx VT_API_KEY "YOUR_KEY"           # Windows
export VT_API_KEY="YOUR_KEY"         # macOS/Linux
```

### 5. Run the app

```bash
python app.py
```

Then open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

## 🧠 How It Works

Each module runs independently inside the Flask app:

* **`/logs`** → Scans uploaded text logs and highlights suspicious activity.
* **`/integrity`** → Computes and compares SHA-256 hashes to detect tampering.
* **`/threat`** → Queries VirusTotal API to assess IP/domain reputation.

Results are displayed in a clean, modern dashboard built with Bootstrap 5 and custom CSS inspired by professional SOC interfaces.

---

## 🌐 Deployment

You can host CyberOpsHub on:

* **Render** → free & simple Flask hosting
* **Railway.app** → modern full-stack deployment
* **Fly.io** → Docker-based app hosting

Add `gunicorn` to your dependencies and set the startup command:

```bash
gunicorn app:app
```


## License

Licensed under the **MIT License** — you’re free to use, modify, and share this project with attribution.

---

## Author

**Mohammed bin Abdul Salam**
Cybersecurity & Data Analytics Enthusiast
 Based in Dubai | Focused on SOC Automation & Threat Analysis

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://www.linkedin.com/in/m-salam/)

---

## Support

If you find this project helpful, consider giving it a **star ⭐** — it helps others discover it and keeps the project growing.

---

**Disclaimer:** This project is intended for educational and defensive cybersecurity use only.  
Do not deploy, scan, or test systems without proper authorization.
