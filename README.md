# Cyops - Security Operations Dashboard

Overview:
CyberOpsHub is a unified web-based Security Operations Center (SOC) dashboard built with Flask, designed to integrate multiple cybersecurity utilities — log monitoring, file-integrity verification, phishing detection, and threat-intelligence lookups — into a single, AI-ready interface.

✨ Key Features:
------------------

Log Monitor: Upload and analyze system logs for failed logins, unauthorized access, or error events.

File Integrity Checker: Compare file hashes (SHA-256) to detect tampering or unauthorized changes.

Threat Intelligence: Query IPs or domains using the VirusTotal API (with demo fallback).

AI Analyst (Preview): A planned virtual SOC assistant that summarizes logs and provides next-step recommendations.

Modular Flask Architecture: Each tool runs independently but is unified under one dashboard for scalability.

Responsive Dashboard UI: Modern SaaS-style interface with dark sidebar, white content cards, and Bootstrap-based layout.

🧰 Tech Stack:
---------------

Backend: Python (Flask, hashlib, requests)

Frontend: HTML5, CSS3, Bootstrap 5, Jinja2

APIs: VirusTotal (with environment variable support)

Utilities: Virtual environments, pip dependencies, and modular file structure

📂 Folder Structure:
---------------------

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


🚀 Setup Instructions:

Clone the repository
----------------------

git clone https://github.com/yourusername/cyberopshub.git
cd cyberopshub


Create a virtual environment
-----------------------------

python -m venv venv
.\venv\Scripts\activate


Install dependencies
----------------------

pip install -r requirements.txt


(Optional) Set your VirusTotal API key
---------------------------------------

setx VT_API_KEY "YOUR_KEY_HERE"


Run the app
--------------

python app.py


Open http://127.0.0.1:5000
 in your browser.

💡 Future Enhancements:

Integrate OpenAI API for AI-powered log summarization and risk scoring

Add real-time alert visualization with charts (using Chart.js or Recharts)

Expand with Shodan and AbuseIPDB integrations

🧑‍💻 Ideal For:
Cybersecurity students and professionals who want to demonstrate SOC operations, Flask development, and threat-intelligence automation in one hands-on project.
