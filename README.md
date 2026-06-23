# 🛡️ Log Sentinel
### AI-Powered Windows Event Log Threat Analyzer

Automatically fetches Windows Event Logs and uses Claude AI to detect malicious activity — no manual log entry required.

---

## 📁 Project Structure

```
log-sentinel/
├── backend/
│   ├── main.py           ← FastAPI server (fetches logs + calls Claude)
│   ├── requirements.txt  ← Python dependencies
│   └── start.bat         ← One-click start script for Windows
└── frontend/
    ├── public/
    │   └── index.html
    ├── src/
    │   ├── index.js
    │   └── App.jsx       ← React dashboard
    └── package.json
```

---

## ⚙️ Setup Instructions

### Step 1 — Get your Anthropic API Key
1. Go to https://console.anthropic.com
2. Create an account and generate an API key
3. Copy the key (starts with `sk-ant-...`)

---

### Step 2 — Start the Python Backend

> **Requires:** Python 3.10+ installed on Windows

```bash
cd backend

# Install dependencies
pip install -r requirements.txt

# Set your API key (Windows Command Prompt)
set ANTHROPIC_API_KEY=sk-ant-your-key-here

# Start the server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**OR** just edit `start.bat`, paste your API key, and double-click it.

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

### Step 3 — Start the React Frontend

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
5. Claude AI analyzes the logs and shows:
   - Overall Risk Level (Critical / High / Medium / Low)
   - Detected threats with descriptions
   - Recommendations for each threat
   - Raw log sample

---

## 🔍 What It Detects

| Event ID | Threat |
|----------|--------|
| 4625 | Failed login attempts / Brute Force |
| 4720 | New user account created |
| 4732 | User added to Administrators group |
| 4648 | Explicit credential logon (Pass-the-Hash) |
| 7045 | Suspicious new service installed |
| 4688 | Suspicious process creation |
| 4697 | Service installed in the system |
| 1102 | Audit log cleared (log tampering) |

---

## 🖥️ Demo Mode

Running the backend on **Mac/Linux**? No problem — it automatically uses realistic mock Windows logs so you can demo the full app without a Windows machine.

---

## 🔄 Auto-Refresh

Enable **Auto-refresh** in the top-right to re-scan every 2 minutes automatically — great for live monitoring demos.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| AI Analysis | Claude claude-sonnet-4-6 (Anthropic) |
| Backend | Python + FastAPI |
| Log Fetching | PowerShell (`Get-WinEvent`) |
| Frontend | React 18 |
| Styling | Inline CSS (dark theme) |

---

## 📌 Notes for Internship Demo

- Run the backend **as Administrator** for full access to Security logs
- The Security channel requires elevated privileges on Windows
- For a live demo, use **Demo Mode** (non-Windows) to show sample threats
- The app detects threats in real-time — no database or ML training needed
