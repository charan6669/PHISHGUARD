# 🛡️ PhishGuard

### Smart URL Phishing Detection & Risk Analysis

PhishGuard is a cybersecurity-focused web application that analyzes URLs and identifies potential phishing indicators.

It uses multiple URL security checks to generate a risk score and classify a URL as:

- 🟢 SAFE
- 🟡 SUSPICIOUS
- 🔴 PHISHING

---

## 🚀 Live Demo

🌐 https://phishguard-1-cv5a.onrender.com

---

## ✨ Features

- 🔐 User Registration & Login
- 🛡️ URL Phishing Detection
- 📊 Risk Score from 0–100%
- 🔎 Suspicious Keyword Detection
- 🌐 IP Address Detection
- 🔒 HTTPS Security Check
- 🔗 Suspicious URL Symbol Detection
- 🌍 Subdomain Analysis
- 📏 URL Length Analysis
- 🚪 Unusual Port Detection
- 📝 Detailed Risk Reasons
- 🕘 Recent Scan History
- 🗄️ SQLite Database
- 📱 Responsive UI

---

## 🧠 How It Works

1. User logs into PhishGuard.
2. User enters a URL.
3. The backend analyzes the URL.
4. Multiple security indicators are checked.
5. A risk score is generated.
6. The URL is classified as SAFE, SUSPICIOUS, or PHISHING.
7. The scan result is stored in the user's scan history.

---

## 🔍 Security Checks

PhishGuard currently checks for:

- Non-HTTPS connections
- IP-based URLs
- Suspicious keywords
- Multiple subdomains
- Excessive URL length
- `@` symbol
- Multiple hyphens
- Unusual network ports

---

## 🛠️ Tech Stack

### Frontend
- HTML5
- CSS3
- JavaScript

### Backend
- Python
- Flask

### Database
- SQLite
- Flask-SQLAlchemy

### Security
- Werkzeug password hashing

### Deployment
- GitHub
- Render

---

## 📂 Project Structure

```text
phishguard/
│
├── app.py
├── requirements.txt
├── phishguard.db
│
├── templates/
│   ├── index.html
│   ├── login.html
│   └── register.html
│
└── static/
    ├── style.css
    └── script.js
