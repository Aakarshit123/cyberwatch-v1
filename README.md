# CyberWatch — Amroha Police Cyber Cell

Forensic intelligence tools for law enforcement:
- **UPI Fraud Graph Analyzer** — Map transaction networks, detect mules & masterminds
- **WhatsApp Forward Chain Tracker** — Trace scam message spread, extract IOCs

---

## Local Setup

```bash
cd cyberwatch
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

---

## Hosting Options

### Option 1: Render.com (Free, Recommended)
1. Push this folder to a GitHub repo
2. Go to https://render.com → New → Web Service
3. Connect your repo
4. Set:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
5. Add `gunicorn` to requirements.txt
6. Deploy — you get a free public URL

### Option 2: Railway.app (Free tier)
1. Push to GitHub
2. Go to https://railway.app → New Project → Deploy from GitHub
3. It auto-detects Flask, set start command: `gunicorn app:app`

### Option 3: PythonAnywhere (Free)
1. Upload files to PythonAnywhere
2. Set WSGI file to point to `app`
3. Free subdomain: yourname.pythonanywhere.com

### For Render/Railway — add gunicorn:
```
flask>=3.0.0
gunicorn>=21.0.0
```

---

## Project Structure

```
cyberwatch/
├── app.py                  # Flask app + API routes
├── requirements.txt
├── tools/
│   ├── upi_analyzer.py     # UPI fraud detection logic
│   └── whatsapp_analyzer.py # WhatsApp parsing + IOC extraction
├── templates/
│   ├── base.html           # Shared nav + styles
│   ├── index.html          # Dashboard homepage
│   ├── upi.html            # UPI Graph tool
│   └── whatsapp.html       # WhatsApp tracker
└── uploads/                # Temp file storage
```

---

## Features

### UPI Fraud Graph
- Input transaction pairs (from/to UPI ID, amount, date)
- Automatic risk scoring per account
- Detects: mule accounts, masterminds, pass-through patterns
- Interactive Cytoscape.js network graph
- Sample data included for demo

### WhatsApp Tracker
- Upload exported .txt chat file
- Detects forwarded messages + "forwarded many times"
- Extracts: URLs, phone numbers, UPI IDs
- 30+ scam keyword detection
- Timeline chart of message activity
- Per-sender risk scoring

---

Built by Aakarshit Bargotra — Cyber Security Intern, Amroha Police × SVU 2026
