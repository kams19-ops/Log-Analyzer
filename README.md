# 🛡️ Log Sentinel
### AI-Powered Windows Event Log Threat Analyzer

Automatically fetches Windows Event Logs and uses an AI model to detect malicious or suspicious activity — no manual log review required.

---

## 📁 Project Structure

```
log-sentinel/
├── backend/
│   ├── main.py           ← FastAPI server (fetches logs + calls Groq AI)
│   ├── requirements.txt  ← Python dependencies
│   └── start.bat         ← One-click start script for Windows
├── frontend/
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── index.js
│   │   └── App.jsx       ← React dashboard
│   └── package.json
└── .gitignore
```

---

## ⚙️ Setup Instructions

### Step 1 — Get a free Groq API key

1. Go to https://console.groq.com
2. Sign up (no credit card required)
3. Go to **API Keys** → **Create API Key**
4. Copy the key (starts with `gsk_...`)

> ⚠️ **Never commit your API key to GitHub.** Set it as an environment variable each session (see below), or in a local `.env`/`start.bat` that you keep out of version control. GitHub's push protection will block commits containing a detected API key — if that happens, remove the key from the file, amend the commit, and revoke + regenerate the key as a precaution.

---

### Step 2 — Start the Python backend

> **Requires:** Python 3.10+ installed on Windows

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Set your API key (PowerShell)
$env:GROQ_API_KEY="gsk_your_key_here"

# Start the server
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

> Run your terminal **as Administrator** if you want to scan the **Security** log channel — Windows requires elevated privileges to read it. **System** and **Application** channels work without admin rights.

---

### Step 3 — Start the React frontend

> **Requires:** Node.js 18+ installed

```bash
cd frontend

# Install dependencies
npm install

# Start the app
npm start
```

The dashboard opens at **http://localhost:3000**

---

## 🚀 How to Use

1. Open **http://localhost:3000** in your browser
2. Select a **Log Channel** (Security / System / Application)
3. Choose **Max Events** and **Time Range**
4. Click **Scan Now**
5. The AI analyzes the logs and shows:
   - Overall risk level (Critical / High / Medium / Low) on a gauge
   - Severity breakdown and top threat categories
   - Detailed findings with recommendations
   - A raw log sample tab

---

## 🔍 What It Detects

| Event ID | Threat |
|----------|--------|
| 4625 | Failed login attempts / brute force |
| 4720 | New user account created |
| 4732 | User added to Administrators group |
| 4648 | Explicit credential logon (pass-the-hash style) |
| 5379 | Credential Manager credentials accessed |
| 7045 | Suspicious new service installed |
| 4688 | Suspicious process creation |
| 1102 | Audit log cleared (log tampering) |

The AI also reasons over log context beyond fixed signatures — e.g. flagging unusual timing, repeated access patterns, or combinations of events that suggest an attack chain.

---

## 🖥️ Demo Mode

For a public/deployed demo, you don't need to host the backend at all.

- **`DEMO_MODE`** in `frontend/src/App.jsx` — set to `true` before deploying. "Scan Now" then returns one of several pre-built realistic scenarios (randomly chosen) instantly, entirely in the browser — no backend call, no server to host.
- **`FORCE_DEMO`** in `backend/main.py` — a separate switch, only relevant if you choose to run a real backend somewhere publicly. Not needed for the simple frontend-only demo above.

To deploy the demo: set `DEMO_MODE = true` in `App.jsx`, then deploy just the `frontend` folder to any static host (Vercel, Netlify, GitHub Pages). That's the entire deployment — no backend hosting, no environment variables, no server costs.

For your own local use with real Windows logs, keep `DEMO_MODE = false` and run the backend as described above.

A website can never read a visitor's local system logs directly — that's a browser security boundary, not a limitation of this app. The deployed version is intentionally a demo for that reason; the real, local-log version only runs when you start the backend on your own Windows machine.

---

## 🔄 Auto-Refresh

Enable **Auto-refresh** in the top-right to re-scan every 2 minutes automatically — useful for simulating continuous monitoring.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| AI Analysis | Groq API — Llama 3.1 (8B Instant) |
| Backend | Python + FastAPI |
| Log Fetching | PowerShell (`Get-WinEvent`) |
| Frontend | React 18, fully responsive (mobile/tablet/desktop) |
| Styling | Inline CSS — black / white / blue / grey theme |

---

## 📌 Notes for Internship Demo

- Run the backend **as Administrator** for full access to Security logs.
- Groq's free tier has a token-per-minute rate limit — the backend caps how many logs are sent per request to stay within it.
- The backend recomputes threat counts from the AI's actual findings list rather than trusting the model's self-reported numbers, since smaller LLMs can be inconsistent with structured JSON fields.
- The app detects threats in real time — no database, no model training, and (outside of demo mode) no stored history between scans.