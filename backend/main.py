"""
Log Sentinel - Backend
Fetches Windows Event Logs and analyzes them using Claude AI
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess
import json
import httpx
import os
from datetime import datetime, timedelta
from typing import Optional
import platform

app = FastAPI(title="Log Sentinel API")

# Allow the frontend to connect. Allowing all origins is fine here since
# FORCE_DEMO mode below never touches real logs or sensitive data.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

# ─────────────────────────────────────────────
# DEMO MODE SWITCH
# ─────────────────────────────────────────────
# Flip this to True before deploying publicly. It makes every scan return a
# safe, pre-baked result instead of reading real logs or calling the AI API
# live — a website can never read a visitor's own machine logs anyway, and
# this avoids spending API credits per visitor.
#
# Keep this False for your own local/Windows use with real logs.
FORCE_DEMO = False

# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    log_channel: str = "Security"
    max_events: int = 50
    hours_back: int = 24

# ─────────────────────────────────────────────
# LOG FETCHING
# ─────────────────────────────────────────────

def fetch_windows_logs_powershell(channel: str, max_events: int, hours_back: int) -> list[dict]:
    """Fetch Windows Event Logs using PowerShell."""
    start_time = (datetime.now() - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%S")

    # PowerShell command to fetch logs as JSON
    ps_command = f"""
    $logs = Get-WinEvent -LogName '{channel}' -MaxEvents {max_events} -ErrorAction SilentlyContinue |
        Where-Object {{ $_.TimeCreated -gt '{start_time}' }} |
        Select-Object @{{N='EventId';E={{$_.Id}}}},
                      @{{N='Level';E={{$_.LevelDisplayName}}}},
                      @{{N='TimeCreated';E={{$_.TimeCreated.ToString('o')}}}},
                      @{{N='Message';E={{$_.Message -replace '\\r\\n',' ' -replace '\\n',' '}}}},
                      @{{N='ProviderName';E={{$_.ProviderName}}}},
                      @{{N='Computer';E={{$_.MachineName}}}}
    $logs | ConvertTo-Json -Depth 2
    """

    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
        capture_output=True,
        text=True,
        timeout=30
    )

    if result.returncode != 0:
        raise RuntimeError(f"PowerShell error: {result.stderr}")

    output = result.stdout.strip()
    if not output or output == "null":
        return []

    data = json.loads(output)
    # PowerShell returns a single object (not list) if only 1 event
    if isinstance(data, dict):
        data = [data]

    return data


def fetch_mock_logs(channel: str, max_events: int) -> list[dict]:
    """Return realistic mock logs for development/demo on non-Windows systems."""
    import random

    templates = [
        # Suspicious events
        {"EventId": 4625, "Level": "Warning",  "ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "An account failed to log on. Subject: Security ID: NULL SID Account Name: - Logon Type: 3 Account For Which Logon Failed: Security ID: NULL SID Account Name: Administrator"},
        {"EventId": 4648, "Level": "Warning",  "ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "A logon was attempted using explicit credentials. Subject: Account Name: SYSTEM Logon GUID: {00000000} Account Whose Credentials Were Used: Account Name: admin@domain.com"},
        {"EventId": 4720, "Level": "Information","ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "A user account was created. Subject: Account Name: SYSTEM New Account: Security ID: S-1-5-21 Account Name: hacker_user"},
        {"EventId": 4732, "Level": "Warning",  "ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "A member was added to a security-enabled local group. Group Name: Administrators Member: Account Name: suspicious_user"},
        {"EventId": 7045, "Level": "Warning",  "ProviderName": "Service Control Manager",             "Message": "A new service was installed in the system. Service Name: MaliciousService Service File Name: C:\\Windows\\Temp\\svchost32.exe"},
        # Normal events
        {"EventId": 4624, "Level": "Information","ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "An account was successfully logged on. Subject: Account Name: SYSTEM Logon Type: 2 New Logon: Account Name: john.doe"},
        {"EventId": 4634, "Level": "Information","ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "An account was logged off. Subject: Account Name: john.doe Logon Type: 2"},
        {"EventId": 1074, "Level": "Information","ProviderName": "USER32",                             "Message": "The process Explorer.EXE has initiated the restart of computer WORKSTATION-01 on behalf of user DOMAIN\\admin for the following reason: Application: Maintenance."},
        {"EventId": 6005, "Level": "Information","ProviderName": "EventLog",                           "Message": "The Event log service was started."},
        {"EventId": 4688, "Level": "Information","ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "A new process has been created. Creator Subject: Account Name: john.doe New Process Name: C:\\Windows\\System32\\cmd.exe"},
    ]

    logs = []
    now = datetime.now()
    for i in range(min(max_events, 20)):
        t = templates[i % len(templates)].copy()
        t["TimeCreated"] = (now - timedelta(minutes=random.randint(1, 1440))).isoformat()
        t["Computer"] = "WORKSTATION-01"
        logs.append(t)

    logs.sort(key=lambda x: x["TimeCreated"], reverse=True)
    return logs


# ─────────────────────────────────────────────
# CLAUDE ANALYSIS
# ─────────────────────────────────────────────

async def analyze_logs_with_claude(logs: list[dict]) -> dict:
    """Send logs to Groq API (Llama 3.1) and get threat analysis."""
    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not set")

    # Groq's free tier caps requests at 6000 tokens/minute.
    # Cap log count and trim message length so we stay safely under that.
    MAX_LOGS_PER_REQUEST = 20
    MAX_MSG_CHARS = 150
    trimmed_logs = logs[:MAX_LOGS_PER_REQUEST]

    log_text = "\n".join([
        f"[{l.get('TimeCreated','')}] EventID={l.get('EventId','')} Level={l.get('Level','')} "
        f"Provider={l.get('ProviderName','')} | {l.get('Message','')[:MAX_MSG_CHARS]}"
        for l in trimmed_logs
    ])

    prompt = f"""You are a Windows security analyst. Analyze these Windows Event Logs and identify any malicious or suspicious activity.

LOGS:
{log_text}

Respond ONLY with a valid JSON object (no markdown, no preamble) with this exact structure:
{{
  "summary": "Brief overall assessment of the log set",
  "risk_level": "Critical|High|Medium|Low",
  "total_analyzed": {len(trimmed_logs)},
  "threats_found": 0,
  "findings": [
    {{
      "event_id": 1234,
      "severity": "Critical|High|Medium|Low|Info",
      "category": "Brute Force|Privilege Escalation|Malware|Persistence|Lateral Movement|Suspicious Process|Account Manipulation|Normal",
      "title": "Short threat title",
      "description": "What happened and why it is suspicious",
      "recommendation": "What to do about it",
      "timestamp": "ISO timestamp from the log"
    }}
  ],
  "normal_events_count": 0
}}

Only include findings for events that are suspicious or malicious. Normal routine events should be counted in normal_events_count but not listed in findings."""

    async with httpx.AsyncClient() as client:
        response = await client.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "max_tokens": 2000,
                "messages": [
                    {"role": "system", "content": "You are a Windows security analyst. Always respond with ONLY valid JSON, no markdown fences, no preamble."},
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=60.0
        )

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail=f"Groq API error: {response.text}")

    content = response.json()["choices"][0]["message"]["content"].strip()

    # Strip any accidental markdown fences
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    content = content.strip()

    parsed = json.loads(content)

    # Smaller models sometimes return a 'threats_found' number that doesn't
    # match the actual length of the 'findings' list. Recompute it ourselves
    # so the dashboard counts are always consistent with what's displayed.
    findings = parsed.get("findings", [])
    parsed["threats_found"] = len(findings)
    parsed["normal_events_count"] = max(len(trimmed_logs) - len(findings), 0)

    return parsed


def get_demo_analysis(channel: str) -> dict:
    """
    Fully pre-baked demo result — used when FORCE_DEMO=true (public deployment).
    No live AI call, no real log access. Same realistic shape as a genuine scan,
    deterministic so the live demo always looks polished.
    """
    now = datetime.now()

    findings = [
        {
            "event_id": 4625,
            "severity": "High",
            "category": "Brute Force",
            "title": "Multiple failed login attempts for account 'Administrator'",
            "description": "Five failed logon attempts were recorded for the Administrator account within a two-minute window, originating from logon type 3 (network). This pattern is consistent with a password-guessing or brute-force attempt rather than normal user error.",
            "recommendation": "Lock the account temporarily, review the source IP/host of the attempts, and enable account lockout policies if not already active.",
            "timestamp": (now - timedelta(hours=2)).isoformat(),
        },
        {
            "event_id": 4732,
            "severity": "Critical",
            "category": "Privilege Escalation",
            "title": "User added to local Administrators group",
            "description": "The account 'suspicious_user' was added to the local Administrators security group shortly after the failed login attempts above. Combined, these two events suggest a possible successful compromise followed by privilege escalation.",
            "recommendation": "Immediately verify whether this change was authorized. If not, remove the account from the Administrators group and investigate how access was obtained.",
            "timestamp": (now - timedelta(hours=1, minutes=55)).isoformat(),
        },
        {
            "event_id": 7045,
            "severity": "Medium",
            "category": "Persistence",
            "title": "New service installed from an unusual path",
            "description": "A new Windows service was registered pointing to an executable located in a temporary directory rather than a standard Program Files location, a common technique used to establish persistence on a compromised host.",
            "recommendation": "Inspect the service binary, verify its digital signature, and remove it if it cannot be attributed to a known, legitimate application.",
            "timestamp": (now - timedelta(hours=1, minutes=40)).isoformat(),
        },
    ]

    raw_logs = [
        {"EventId": 4625, "Level": "Warning", "TimeCreated": findings[0]["timestamp"], "ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "An account failed to log on. Account Name: Administrator. Logon Type: 3."},
        {"EventId": 4732, "Level": "Warning", "TimeCreated": findings[1]["timestamp"], "ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "A member was added to a security-enabled local group. Group: Administrators. Member: suspicious_user."},
        {"EventId": 7045, "Level": "Warning", "TimeCreated": findings[2]["timestamp"], "ProviderName": "Service Control Manager", "Message": "A new service was installed. Service Name: UpdateHelper. Service File Name: C:\\Windows\\Temp\\svchost32.exe."},
        {"EventId": 4624, "Level": "Information", "TimeCreated": (now - timedelta(hours=1)).isoformat(), "ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "An account was successfully logged on. Account Name: john.doe. Logon Type: 2."},
        {"EventId": 4634, "Level": "Information", "TimeCreated": (now - timedelta(minutes=40)).isoformat(), "ProviderName": "Microsoft-Windows-Security-Auditing", "Message": "An account was logged off. Account Name: john.doe."},
    ]

    return {
        "summary": (
            "This is a demonstration scan using pre-built sample data. It illustrates how Log Sentinel "
            "would flag a brute-force login attempt followed by privilege escalation and a persistence "
            "mechanism — a realistic attack chain pattern. Live scans of an actual machine are only "
            "available when running the backend locally, since a browser cannot read another computer's "
            "system logs."
        ),
        "risk_level": "Critical",
        "total_analyzed": len(raw_logs),
        "threats_found": len(findings),
        "findings": findings,
        "normal_events_count": len(raw_logs) - len(findings),
        "raw_logs": raw_logs,
        "demo_mode": True,
        "fetched_at": now.isoformat(),
        "channel": channel,
    }


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "Log Sentinel API running", "os": platform.system(), "demo_mode": FORCE_DEMO}


@app.get("/logs/channels")
def get_channels():
    """Return available log channels."""
    return {
        "channels": ["Security", "System", "Application"],
        "descriptions": {
            "Security": "Login attempts, privilege changes, account activity",
            "System":   "Driver failures, service changes, hardware events",
            "Application": "App errors, suspicious installs, crash reports"
        }
    }


@app.post("/logs/analyze")
async def analyze(req: AnalyzeRequest):
    """Fetch logs and analyze them with Groq, or return pre-baked demo data when deployed publicly."""

    # Public deployments always return safe, pre-baked demo data — a browser
    # cannot read a visitor's own machine logs, and we don't want to spend
    # API credits per visitor or expose any real backend host's logs.
    if FORCE_DEMO:
        return get_demo_analysis(req.log_channel)

    is_windows = platform.system() == "Windows"

    try:
        if is_windows:
            logs = fetch_windows_logs_powershell(req.log_channel, req.max_events, req.hours_back)
        else:
            # Demo mode on non-Windows
            logs = fetch_mock_logs(req.log_channel, req.max_events)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log fetch failed: {str(e)}")

    if not logs:
        return {
            "summary": "No logs found in the specified time range.",
            "risk_level": "Low",
            "total_analyzed": 0,
            "threats_found": 0,
            "findings": [],
            "normal_events_count": 0,
            "raw_logs": [],
            "demo_mode": not is_windows
        }

    analysis = await analyze_logs_with_claude(logs)
    analysis["raw_logs"] = logs[:10]   # Return sample of raw logs for the UI
    analysis["demo_mode"] = not is_windows
    analysis["fetched_at"] = datetime.now().isoformat()
    analysis["channel"] = req.log_channel

    return analysis


@app.get("/health")
def health():
    return {"status": "ok", "api_key_set": bool(GROQ_API_KEY), "demo_mode": FORCE_DEMO}