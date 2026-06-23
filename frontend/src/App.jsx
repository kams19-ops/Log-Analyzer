import { useState, useEffect, useCallback } from "react";

// Flip this to true before deploying the demo publicly (e.g. on Vercel).
// When true, "Scan Now" returns fixed sample data instantly — no backend
// needed at all. Keep it false for local development against your real
// Python backend (see backend/main.py).
const DEMO_MODE = false;

// Only used when DEMO_MODE is false — your local backend's address.
const API = "http://localhost:8000";

function getStaticDemoResult(channel) {
  const now = new Date();
  const minus = (mins) => new Date(now.getTime() - mins * 60000).toISOString();

  // ── Scenario 1: Brute force → privilege escalation → persistence (Critical) ──
  const scenarioAttackChain = () => {
    const findings = [
      {
        event_id: 4625, severity: "High", category: "Brute Force",
        title: "Multiple failed login attempts for account 'Administrator'",
        description: "Five failed logon attempts were recorded for the Administrator account within a two-minute window, originating from logon type 3 (network). This pattern is consistent with a password-guessing or brute-force attempt rather than normal user error.",
        recommendation: "Lock the account temporarily, review the source IP/host of the attempts, and enable account lockout policies if not already active.",
        timestamp: minus(120),
      },
      {
        event_id: 4732, severity: "Critical", category: "Privilege Escalation",
        title: "User added to local Administrators group",
        description: "The account 'suspicious_user' was added to the local Administrators security group shortly after the failed login attempts above. Combined, these two events suggest a possible successful compromise followed by privilege escalation.",
        recommendation: "Immediately verify whether this change was authorized. If not, remove the account from the Administrators group and investigate how access was obtained.",
        timestamp: minus(115),
      },
      {
        event_id: 7045, severity: "Medium", category: "Persistence",
        title: "New service installed from an unusual path",
        description: "A new Windows service was registered pointing to an executable located in a temporary directory rather than a standard Program Files location, a common technique used to establish persistence on a compromised host.",
        recommendation: "Inspect the service binary, verify its digital signature, and remove it if it cannot be attributed to a known, legitimate application.",
        timestamp: minus(100),
      },
    ];
    const raw_logs = [
      { EventId: 4625, Level: "Warning", TimeCreated: findings[0].timestamp, ProviderName: "Microsoft-Windows-Security-Auditing", Message: "An account failed to log on. Account Name: Administrator. Logon Type: 3." },
      { EventId: 4732, Level: "Warning", TimeCreated: findings[1].timestamp, ProviderName: "Microsoft-Windows-Security-Auditing", Message: "A member was added to a security-enabled local group. Group: Administrators. Member: suspicious_user." },
      { EventId: 7045, Level: "Warning", TimeCreated: findings[2].timestamp, ProviderName: "Service Control Manager", Message: "A new service was installed. Service Name: UpdateHelper. Service File Name: C:\\Windows\\Temp\\svchost32.exe." },
      { EventId: 4624, Level: "Information", TimeCreated: minus(60), ProviderName: "Microsoft-Windows-Security-Auditing", Message: "An account was successfully logged on. Account Name: john.doe. Logon Type: 2." },
      { EventId: 4634, Level: "Information", TimeCreated: minus(40), ProviderName: "Microsoft-Windows-Security-Auditing", Message: "An account was logged off. Account Name: john.doe." },
    ];
    return {
      summary: "A brute-force login attempt was followed by privilege escalation and a persistence mechanism — a realistic attack chain pattern requiring immediate review.",
      risk_level: "Critical", findings, raw_logs,
    };
  };

  // ── Scenario 2: Suspicious credential access (High) ──
  const scenarioCredentialAccess = () => {
    const findings = [
      {
        event_id: 5379, severity: "High", category: "Suspicious Process",
        title: "Credential Manager credentials read repeatedly",
        description: "Saved credentials in Windows Credential Manager were read multiple times within a short window by a non-system process. This can indicate a credential-harvesting tool, though it may also reflect legitimate password-manager activity.",
        recommendation: "Identify the requesting process. If it cannot be attributed to a known credential manager or browser, treat as a potential credential theft attempt and isolate the host.",
        timestamp: minus(45),
      },
      {
        event_id: 4648, severity: "Medium", category: "Lateral Movement",
        title: "Logon attempted using explicit credentials",
        description: "A process used the runas-style explicit credential logon technique to authenticate as a different account than the one currently logged in — a common method for lateral movement between machines.",
        recommendation: "Confirm whether this matches a known administrative task or scheduled job. If not, investigate the source process and account involved.",
        timestamp: minus(30),
      },
    ];
    const raw_logs = [
      { EventId: 5379, Level: "Information", TimeCreated: findings[0].timestamp, ProviderName: "Microsoft-Windows-Security-Auditing", Message: "Credential Manager credentials were read. Subject: Account Name: garvit." },
      { EventId: 4648, Level: "Information", TimeCreated: findings[1].timestamp, ProviderName: "Microsoft-Windows-Security-Auditing", Message: "A logon was attempted using explicit credentials. Account Whose Credentials Were Used: admin@domain.com." },
      { EventId: 4624, Level: "Information", TimeCreated: minus(20), ProviderName: "Microsoft-Windows-Security-Auditing", Message: "An account was successfully logged on. Account Name: garvit. Logon Type: 2." },
      { EventId: 4634, Level: "Information", TimeCreated: minus(10), ProviderName: "Microsoft-Windows-Security-Auditing", Message: "An account was logged off. Account Name: garvit." },
    ];
    return {
      summary: "Repeated credential access combined with an explicit-credential logon suggests possible unauthorized access. No confirmed malicious activity, but the pattern warrants investigation.",
      risk_level: "High", findings, raw_logs,
    };
  };

  // ── Scenario 3: Minor configuration warning (Low) ──
  const scenarioLowRisk = () => {
    const findings = [
      {
        event_id: 10016, severity: "Low", category: "Suspicious Process",
        title: "Distributed COM application permission issue",
        description: "An application attempted to launch a COM server without the required permissions. This is most often caused by a misconfigured or outdated application rather than malicious activity.",
        recommendation: "No immediate action required. If this recurs frequently, identify the application generating the warning and update or reconfigure it.",
        timestamp: minus(35),
      },
    ];
    const raw_logs = [
      { EventId: 10016, Level: "Warning", TimeCreated: findings[0].timestamp, ProviderName: "Microsoft-Windows-DistributedCOM", Message: "The application-specific permission settings do not grant Local Activation permission for the COM Server application." },
      { EventId: 4624, Level: "Information", TimeCreated: minus(50), ProviderName: "Microsoft-Windows-Security-Auditing", Message: "An account was successfully logged on. Account Name: john.doe. Logon Type: 2." },
      { EventId: 6005, Level: "Information", TimeCreated: minus(90), ProviderName: "EventLog", Message: "The Event log service was started." },
    ];
    return {
      summary: "No clear malicious activity detected. A configuration warning related to Distributed COM was observed, most likely caused by a misconfigured application rather than a threat.",
      risk_level: "Low", findings, raw_logs,
    };
  };

  // ── Scenario 4: Clean scan, nothing flagged (Low) ──
  const scenarioClean = () => {
    const raw_logs = [
      { EventId: 4624, Level: "Information", TimeCreated: minus(15), ProviderName: "Microsoft-Windows-Security-Auditing", Message: "An account was successfully logged on. Account Name: john.doe. Logon Type: 2." },
      { EventId: 4634, Level: "Information", TimeCreated: minus(5), ProviderName: "Microsoft-Windows-Security-Auditing", Message: "An account was logged off. Account Name: john.doe." },
      { EventId: 6005, Level: "Information", TimeCreated: minus(120), ProviderName: "EventLog", Message: "The Event log service was started." },
      { EventId: 1074, Level: "Information", TimeCreated: minus(150), ProviderName: "USER32", Message: "The process Explorer.EXE has initiated a restart on behalf of user DOMAIN\\admin for the following reason: Application: Maintenance." },
    ];
    return {
      summary: "All analyzed events fall within expected behavior. No suspicious or malicious activity detected in this scan.",
      risk_level: "Low", findings: [], raw_logs,
    };
  };

  const scenarios = [scenarioAttackChain, scenarioCredentialAccess, scenarioLowRisk, scenarioClean];
  const chosen = scenarios[Math.floor(Math.random() * scenarios.length)]();

  return {
    summary: `${chosen.summary} (This is a demonstration scan using sample data — live scans of an actual machine are only available when running the backend locally, since a browser cannot read another computer's system logs.)`,
    risk_level: chosen.risk_level,
    total_analyzed: chosen.raw_logs.length,
    threats_found: chosen.findings.length,
    findings: chosen.findings,
    normal_events_count: chosen.raw_logs.length - chosen.findings.length,
    raw_logs: chosen.raw_logs,
    demo_mode: true,
    fetched_at: now.toISOString(),
    channel,
  };
}

function useViewport() {
  const [width, setWidth] = useState(typeof window !== "undefined" ? window.innerWidth : 1200);
  useEffect(() => {
    const onResize = () => setWidth(window.innerWidth);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);
  return width;
}

// ── Palette: black / blue / white / grey only ──
const BG          = "#FFFFFF";   // page background
const PANEL       = "#FFFFFF";   // card/panel background
const PANEL_2     = "#F5F6F8";   // input/select background
const LINE        = "#E2E5EA";   // borders/dividers
const TEXT        = "#13151A";   // primary text
const TEXT_MUTED  = "#6B7280";   // secondary text
const BLUE        = "#2563EB";   // accent
const BLUE_DIM    = "#DBEAFE";
const WHITE       = "#FFFFFF";

const HEADER_BG    = "#0F1C3D";  // navy derived from accent blue hue, not generic near-black
const HEADER_LINE  = "#1F2D52";
const HEADER_TEXT  = "#FFFFFF";
const HEADER_MUTED = "#9FB0D6";

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
// Blue ramp for severity on light background — darker blue = more severe
const SEVERITY_COLOR = {
  Critical: "#1E3A8A",
  High:     "#2563EB",
  Medium:   "#60A5FA",
  Low:      "#93C5FD",
  Info:     "#C7DBFB",
};

function categoryIcon(category) {
  const c = (category || "").toLowerCase();
  if (c.includes("brute") || c.includes("force")) {
    return <path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z" stroke="currentColor" strokeWidth="1.6" fill="none" />;
  }
  if (c.includes("privilege") || c.includes("escalation")) {
    return <path d="M12 19V5M6 11l6-6 6 6" stroke="currentColor" strokeWidth="1.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />;
  }
  if (c.includes("malware")) {
    return <><circle cx="12" cy="12" r="7" stroke="currentColor" strokeWidth="1.6" fill="none" /><path d="M9 9l6 6M15 9l-6 6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></>;
  }
  if (c.includes("persist")) {
    return <path d="M12 2v6M12 16v6M4.9 4.9l4.2 4.2M14.9 14.9l4.2 4.2M2 12h6M16 12h6M4.9 19.1l4.2-4.2M14.9 9.1l4.2-4.2" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />;
  }
  if (c.includes("lateral")) {
    return <><circle cx="6" cy="12" r="2.5" stroke="currentColor" strokeWidth="1.6" fill="none" /><circle cx="18" cy="6" r="2.5" stroke="currentColor" strokeWidth="1.6" fill="none" /><circle cx="18" cy="18" r="2.5" stroke="currentColor" strokeWidth="1.6" fill="none" /><path d="M8.3 11l7.4-3.7M8.3 13l7.4 3.7" stroke="currentColor" strokeWidth="1.6" /></>;
  }
  if (c.includes("process")) {
    return <><rect x="4" y="4" width="16" height="16" rx="2" stroke="currentColor" strokeWidth="1.6" fill="none" /><path d="M9 12h6M9 8.5h6M9 15.5h3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></>;
  }
  if (c.includes("account")) {
    return <><circle cx="12" cy="8" r="3.2" stroke="currentColor" strokeWidth="1.6" fill="none" /><path d="M5 20c0-3.5 3.1-6 7-6s7 2.5 7 6" stroke="currentColor" strokeWidth="1.6" fill="none" strokeLinecap="round" /></>;
  }
  if (c.includes("normal")) {
    return <path d="M5 13l4 4L19 7" stroke="currentColor" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round" />;
  }
  // default — generic flag/marker icon
  return <path d="M6 21V4h11l-2.5 4L17 12H6" stroke="currentColor" strokeWidth="1.6" fill="none" strokeLinejoin="round" />;
}

function fmtTime(t) {
  if (!t) return "";
  return t.slice(0, 19).replace("T", " ");
}

function normalizeSeverity(raw) {
  const s = (raw || "").toLowerCase();
  if (s.includes("critical")) return "Critical";
  if (s.includes("high"))     return "High";
  if (s.includes("medium"))   return "Medium";
  if (s.includes("warn"))     return "Medium";   // AI sometimes returns "Warning" instead of a severity tier
  if (s.includes("low"))      return "Low";
  return "Info";
}

function computeStats(result) {
  const findings = result?.findings || [];

  const sevCounts = {};
  SEVERITY_ORDER.forEach(s => (sevCounts[s] = 0));
  findings.forEach(f => {
    const s = normalizeSeverity(f.severity);
    sevCounts[s] = (sevCounts[s] || 0) + 1;
  });

  const catCounts = {};
  findings.forEach(f => {
    const c = f.category || "Uncategorized";
    catCounts[c] = (catCounts[c] || 0) + 1;
  });
  const topCategories = Object.entries(catCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);

  const maxSevCount = Math.max(1, ...Object.values(sevCounts));
  const totalFindings = findings.length || 1;

  return { sevCounts, maxSevCount, topCategories, totalFindings };
}

const RISK_ORDER = ["Low", "Medium", "High", "Critical"];
const RISK_COLOR = {
  Low:      "#93C5FD",
  Medium:   "#60A5FA",
  High:     "#2563EB",
  Critical: "#1E3A8A",
};

// ── Semicircular risk gauge — single strong visual instead of two sparse panels ──
function RiskGauge({ riskLevel, severityCounts, compact }) {
  const size = compact ? 170 : 220;
  const cx = size / 2;
  const cy = size / 2 - (compact ? 4 : 6);
  const r = compact ? 64 : 86;
  const strokeWidth = compact ? 14 : 18;
  const svgHeight = compact ? 132 : 170; // tall enough for the arc plus both text labels below it

  const levelIndex = Math.max(0, RISK_ORDER.indexOf(riskLevel));
  const frac = (levelIndex + 1) / RISK_ORDER.length;

  const startAngle = 180;
  const endAngle = 0;
  const angleForFrac = (f) => startAngle + (endAngle - startAngle) * f;

  const toXY = (angleDeg) => {
    const a = (angleDeg * Math.PI) / 180;
    return [cx + r * Math.cos(a), cy - r * Math.sin(a)];
  };

  const polarArc = (fromDeg, toDeg) => {
    const [x1, y1] = toXY(fromDeg);
    const [x2, y2] = toXY(toDeg);
    const largeArc = Math.abs(fromDeg - toDeg) > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`;
  };

  const needleAngle = angleForFrac(frac);
  const [needleX, needleY] = toXY(needleAngle);
  const color = RISK_COLOR[riskLevel] || TEXT_MUTED;

  const totalFindings = Object.values(severityCounts || {}).reduce((a, b) => a + b, 0);

  return (
    <svg width={size} height={svgHeight} viewBox={`0 0 ${size} ${svgHeight}`}>
      <path d={polarArc(180, 0)} stroke={LINE} strokeWidth={strokeWidth} fill="none" strokeLinecap="round" />
      <path d={polarArc(180, angleForFrac(frac))} stroke={color} strokeWidth={strokeWidth} fill="none" strokeLinecap="round" />
      <line x1={cx} y1={cy} x2={needleX} y2={needleY} stroke={TEXT} strokeWidth="2.5" strokeLinecap="round" />
      <circle cx={cx} cy={cy} r="5" fill={TEXT} />
      <text x={cx} y={cy + (compact ? 26 : 34)} textAnchor="middle" fontSize={compact ? "16" : "20"} fontWeight="700" fill={TEXT}>
        {riskLevel}
      </text>
      <text x={cx} y={cy + (compact ? 41 : 52)} textAnchor="middle" fontSize={compact ? "9.5" : "10.5"} fill={TEXT_MUTED}>
        {totalFindings} finding{totalFindings === 1 ? "" : "s"}
      </text>
    </svg>
  );
}

export default function App() {
  const [channel, setChannel]     = useState("Security");
  const [maxEvents, setMaxEvents] = useState(50);
  const [hoursBack, setHoursBack] = useState(24);
  const [loading, setLoading]     = useState(false);
  const [result, setResult]       = useState(null);
  const [error, setError]         = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [expandedIdx, setExpandedIdx] = useState(null);
  const [activeTab, setActiveTab] = useState("threats");

  const analyze = useCallback(async () => {
    setLoading(true);
    setError(null);

    // Demo deployments skip the backend entirely — just return static data.
    if (DEMO_MODE) {
      setTimeout(() => {
        setResult(getStaticDemoResult(channel));
        setLastRefresh(new Date());
        setLoading(false);
      }, 500); // small delay so "Scanning..." is visible, feels like a real scan
      return;
    }

    try {
      const res = await fetch(`${API}/logs/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          log_channel: channel,
          max_events:  maxEvents,
          hours_back:  hoursBack,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Server error");
      }
      const data = await res.json();
      setResult(data);
      setLastRefresh(new Date());
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [channel, maxEvents, hoursBack]);

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(analyze, 2 * 60 * 1000);
    return () => clearInterval(id);
  }, [autoRefresh, analyze]);

  const stats = result ? computeStats(result) : null;
  const width = useViewport();
  const isMobile = width <= 640;
  const isTablet = width > 640 && width <= 900;

  return (
    <div style={styles.root}>
      {/* ── Header ── */}
      <header style={{
        ...styles.header,
        flexDirection: "row",
        alignItems: "center",
        justifyContent: "space-between",
        padding: isMobile ? "18px 16px" : "18px 32px",
        gap: isMobile ? 10 : 0,
      }}>
        <div style={{ ...styles.headerLeft, gap: isMobile ? 8 : 14 }}>
          <div style={styles.logo}>
            <svg width={isMobile ? "22" : "26"} height={isMobile ? "22" : "26"} viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 6v6c0 5 4 8.5 9 10 5-1.5 9-5 9-10V6l-9-4z" stroke={BLUE} strokeWidth="1.6" />
            </svg>
          </div>
          <div>
            <h1 style={{ ...styles.title, fontSize: isMobile ? 16 : 21 }}>Log Sentinel</h1>
            <p style={{ ...styles.subtitle, fontSize: isMobile ? 10.5 : 12 }}>Windows Event Log Threat Analyzer</p>
          </div>
        </div>
        <div style={{
          ...styles.headerRight,
          flexDirection: isMobile ? "column" : "row",
          alignItems: "flex-end",
          gap: isMobile ? 4 : 18,
          flexShrink: 0,
        }}>
          {result?.demo_mode && <span style={styles.demoBadge}>Demo data</span>}
          {!isMobile && lastRefresh && <span style={styles.lastScan}>Last scan: {lastRefresh.toLocaleTimeString()}</span>}
          <label style={{ ...styles.autoLabel, fontSize: isMobile ? 11.5 : 13, whiteSpace: "nowrap" }}>
            <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} style={{ marginRight: 6 }} />
            {isMobile ? "Auto-refresh" : "Auto-refresh (2 min)"}
          </label>
        </div>
      </header>

      <div style={{ ...styles.page, padding: isMobile ? "20px 16px 48px" : "28px 32px 60px" }}>
        {/* ── Controls ── */}
        <section style={{
          ...styles.controls,
          flexDirection: isMobile ? "column" : "row",
          alignItems: isMobile ? "stretch" : "flex-end",
        }}>
          <div style={{ ...styles.controlGroup, width: isMobile ? "100%" : "auto" }}>
            <label style={styles.label}>Log channel</label>
            <select value={channel} onChange={e => setChannel(e.target.value)} style={{ ...styles.select, width: isMobile ? "100%" : 230, minWidth: 0 }}>
              <option value="Security">Security — Login &amp; Account Events</option>
              <option value="System">System — Driver &amp; Service Events</option>
              <option value="Application">Application — App &amp; Install Events</option>
            </select>
          </div>

          <div style={{ ...styles.controlGroup, width: isMobile ? "100%" : "auto" }}>
            <label style={styles.label}>Max events</label>
            <select value={maxEvents} onChange={e => setMaxEvents(Number(e.target.value))} style={{ ...styles.select, width: isMobile ? "100%" : 230, minWidth: 0 }}>
              {[25, 50, 100, 200].map(n => <option key={n} value={n}>{n} events</option>)}
            </select>
          </div>

          <div style={{ ...styles.controlGroup, width: isMobile ? "100%" : "auto" }}>
            <label style={styles.label}>Time range</label>
            <select value={hoursBack} onChange={e => setHoursBack(Number(e.target.value))} style={{ ...styles.select, width: isMobile ? "100%" : 230, minWidth: 0 }}>
              <option value={1}>Last 1 hour</option>
              <option value={6}>Last 6 hours</option>
              <option value={24}>Last 24 hours</option>
              <option value={72}>Last 3 days</option>
            </select>
          </div>

          <button onClick={analyze} disabled={loading} style={{
            ...styles.scanBtn,
            opacity: loading ? 0.7 : 1,
            marginLeft: isMobile ? 0 : "auto",
            justifyContent: "center",
            width: isMobile ? "100%" : "auto",
          }}>
            <svg
              width="16" height="16" viewBox="0 0 24 24" fill="none"
              style={{ animation: loading ? "spin 0.8s linear infinite" : "none" }}
            >
              <path
                d="M3 12a9 9 0 0 1 15.5-6.5M21 12a9 9 0 0 1-15.5 6.5"
                stroke="currentColor" strokeWidth="2" strokeLinecap="round"
              />
              <path d="M18 3v4h-4M6 21v-4h4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            {loading ? "Scanning..." : "Scan Now"}
          </button>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </section>

        {error && (
          <div style={{ ...styles.errorBox, padding: isMobile ? "12px 14px" : "14px 18px" }}>
            <strong>Error:</strong> {error}
            <div style={styles.errorHint}>Make sure the Python backend is running on port 8000.</div>
          </div>
        )}

        {result && (
          <>
            {/* ── Summary cards ── */}
            <div style={{
              ...styles.cards,
              gridTemplateColumns: isMobile ? "1fr 1fr" : isTablet ? "1fr 1fr" : "repeat(4, 1fr)",
              gap: isMobile ? 10 : 16,
            }}>
              <div style={{ ...styles.card, padding: isMobile ? "14px 14px" : "18px 20px" }}>
                <div style={styles.cardLabel}>Overall risk</div>
                <div style={{ ...styles.cardValue, fontSize: isMobile ? 20 : 26 }}>{result.risk_level}</div>
              </div>
              <div style={{ ...styles.card, padding: isMobile ? "14px 14px" : "18px 20px" }}>
                <div style={styles.cardLabel}>Events analyzed</div>
                <div style={{ ...styles.cardValue, fontSize: isMobile ? 20 : 26 }}>{result.total_analyzed}</div>
              </div>
              <div style={{ ...styles.card, padding: isMobile ? "14px 14px" : "18px 20px" }}>
                <div style={styles.cardLabel}>Threats found</div>
                <div style={{ ...styles.cardValue, fontSize: isMobile ? 20 : 26 }}>{result.threats_found}</div>
              </div>
              <div style={{ ...styles.card, padding: isMobile ? "14px 14px" : "18px 20px" }}>
                <div style={styles.cardLabel}>Normal events</div>
                <div style={{ ...styles.cardValue, fontSize: isMobile ? 20 : 26 }}>{result.normal_events_count}</div>
              </div>
            </div>

            <div style={{ ...styles.summaryBox, padding: isMobile ? "12px 14px" : "14px 18px" }}>{result.summary}</div>

            {/* ── Risk Gauge ── */}
            {stats && result.findings && result.findings.length > 0 && (
              <div style={{
                ...styles.gaugePanel,
                flexDirection: isMobile ? "column" : "row",
                alignItems: isMobile ? "stretch" : "center",
                padding: isMobile ? "18px 16px" : "24px 28px",
                gap: isMobile ? 18 : 28,
              }}>
                <div style={{
                  ...styles.gaugeCol,
                  width: isMobile ? "100%" : "auto",
                  justifyContent: "center",
                }}>
                  <RiskGauge riskLevel={result.risk_level} severityCounts={stats.sevCounts} compact={isMobile} />
                </div>

                <div style={isMobile
                  ? { ...styles.gaugeDivider, width: "100%", height: 1, alignSelf: "stretch" }
                  : styles.gaugeDivider
                } />

                <div style={styles.gaugeStatsCol}>
                  <div style={styles.gaugeStatsTitle}>Severity breakdown</div>
                  <div style={styles.gaugeLegend}>
                    {SEVERITY_ORDER.filter(s => stats.sevCounts[s] > 0).map(s => (
                      <div key={s} style={styles.legendRow}>
                        <span style={{ ...styles.legendDot, background: SEVERITY_COLOR[s] }} />
                        <span style={styles.legendLabel}>{s}</span>
                        <span style={styles.legendValue}>{stats.sevCounts[s]}</span>
                      </div>
                    ))}
                  </div>

                  <div style={{ ...styles.gaugeStatsTitle, marginTop: 18 }}>Top categories</div>
                  <div style={{
                    ...styles.categoryGrid,
                    gridTemplateColumns: isMobile ? "1fr 1fr" : "repeat(3, 1fr)",
                  }}>
                    {stats.topCategories.map(([cat, count]) => (
                      <div key={cat} style={styles.categoryCard}>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" style={{ color: BLUE }}>
                          {categoryIcon(cat)}
                        </svg>
                        <div style={styles.categoryCount}>{count}</div>
                        <div style={styles.categoryLabel}>{cat}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── Tabs ── */}
            <div style={styles.tabs}>
              <button onClick={() => setActiveTab("threats")} style={{
                ...styles.tab,
                marginRight: isMobile ? 16 : 28,
                fontSize: isMobile ? 12.5 : 13.5,
                ...(activeTab === "threats" ? styles.tabActive : {}),
              }}>
                Threats ({result.findings?.length || 0})
              </button>
              <button onClick={() => setActiveTab("raw")} style={{
                ...styles.tab,
                marginRight: isMobile ? 16 : 28,
                fontSize: isMobile ? 12.5 : 13.5,
                ...(activeTab === "raw" ? styles.tabActive : {}),
              }}>
                Raw Logs (sample)
              </button>
            </div>

            {activeTab === "threats" && (
              <div style={styles.findingsWrap}>
                {(!result.findings || result.findings.length === 0) ? (
                  <div style={{ ...styles.emptyState, padding: isMobile ? "32px 16px" : "50px 32px" }}>
                    <div style={styles.emptyTitle}>No threats detected</div>
                    <div style={styles.emptyBody}>All analyzed events appear normal.</div>
                  </div>
                ) : (
                  result.findings.map((f, i) => {
                    const isOpen = expandedIdx === i;
                    const dot = SEVERITY_COLOR[normalizeSeverity(f.severity)] || TEXT_MUTED;
                    return (
                      <div key={i} style={styles.finding}>
                        <div style={{
                          ...styles.findingHeader,
                          padding: isMobile ? "12px 14px" : "14px 18px",
                          alignItems: "flex-start",
                        }} onClick={() => setExpandedIdx(isOpen ? null : i)}>
                          <div style={{ ...styles.findingLeft, flexWrap: isMobile ? "wrap" : "nowrap" }}>
                            <span style={{ ...styles.sevBadge, color: dot, borderColor: dot }}>{f.severity}</span>
                            <div>
                              <div style={{ ...styles.findingTitle, fontSize: isMobile ? 13.5 : 14 }}>{f.title}</div>
                              <div style={styles.findingMeta}>
                                EventID {f.event_id} · {f.category} · {fmtTime(f.timestamp)}
                              </div>
                            </div>
                          </div>
                          <span style={styles.chevron}>{isOpen ? "−" : "+"}</span>
                        </div>

                        {isOpen && (
                          <div style={{ ...styles.findingBody, padding: isMobile ? "0 14px 14px" : "0 18px 16px" }}>
                            <div style={styles.findingSection}>
                              <div style={styles.findingSectionTitle}>What happened</div>
                              <p style={styles.findingText}>{f.description}</p>
                            </div>
                            <div style={styles.findingSection}>
                              <div style={styles.findingSectionTitle}>Recommendation</div>
                              <p style={styles.findingText}>{f.recommendation}</p>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            )}

            {activeTab === "raw" && (
              <div style={styles.rawWrap}>
                {(result.raw_logs || []).map((log, i) => (
                  <div key={i} style={{ ...styles.rawLog, padding: isMobile ? "10px 14px" : "12px 16px" }}>
                    <div style={{ ...styles.rawLogHeader, flexWrap: "wrap", gap: isMobile ? 8 : 16 }}>
                      <span style={styles.rawEventId}>Event {log.EventId}</span>
                      <span style={styles.rawMeta}>{fmtTime(log.TimeCreated)}</span>
                      <span style={styles.rawMeta}>{log.Level}</span>
                    </div>
                    <div style={styles.rawLogMsg}>{log.Message?.slice(0, 300)}</div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {!result && !loading && !error && (
          <div style={{ ...styles.emptyStateMain, padding: isMobile ? "48px 16px" : "90px 32px" }}>
            <div style={styles.emptyMainTitle}>Ready to scan</div>
            <div style={styles.emptyBody}>
              Configure your settings above and click <strong style={{ color: TEXT }}>Scan Now</strong> to begin.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// STYLES
// ─────────────────────────────────────────────
const FONT = "-apple-system, 'Segoe UI', Arial, sans-serif";

const styles = {
  root: { minHeight: "100vh", background: BG, color: TEXT, fontFamily: FONT },
  page: { maxWidth: 1200, margin: "0 auto", padding: "28px 32px 60px" },

  header: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    padding: "18px 32px", borderBottom: `1px solid ${HEADER_LINE}`, background: HEADER_BG,
  },
  headerLeft: { display: "flex", alignItems: "center", gap: 14 },
  logo: { display: "flex", alignItems: "center", justifyContent: "center" },
  title: { margin: 0, fontSize: 21, fontWeight: 700, color: HEADER_TEXT },
  subtitle: { margin: 0, fontSize: 12, color: HEADER_MUTED, marginTop: 2 },
  headerRight: { display: "flex", alignItems: "center", gap: 18 },
  demoBadge: {
    border: `1px solid ${BLUE}`, color: BLUE, fontSize: 11, fontWeight: 600,
    padding: "3px 10px", borderRadius: 6, letterSpacing: 0.4,
  },
  lastScan: { color: HEADER_MUTED, fontSize: 12 },
  autoLabel: { color: HEADER_MUTED, fontSize: 13, cursor: "pointer", userSelect: "none" },

  controls: {
    display: "flex", gap: 18, alignItems: "flex-end", flexWrap: "wrap",
    padding: "20px 0 28px",
  },
  controlGroup: { display: "flex", flexDirection: "column", gap: 7 },
  label: { fontSize: 11, color: TEXT_MUTED, textTransform: "uppercase", letterSpacing: 0.6 },
  select: {
    background: PANEL_2, color: TEXT, border: `1px solid ${LINE}`,
    borderRadius: 10, padding: "12px 16px", fontSize: 14, cursor: "pointer",
    minWidth: 230, fontFamily: FONT,
  },
  scanBtn: {
    background: BLUE, color: WHITE, border: "none", borderRadius: 10,
    padding: "13px 28px", fontSize: 14, fontWeight: 600, cursor: "pointer",
    marginLeft: "auto", fontFamily: FONT,
    display: "flex", alignItems: "center", gap: 8,
  },

  errorBox: {
    margin: "0 0 24px", background: "#FEF2F2", border: `1px solid #FCA5A5`,
    color: "#991B1B", borderRadius: 10, padding: "14px 18px", fontSize: 13,
  },
  errorHint: { marginTop: 4, fontSize: 12, color: "#B91C1C" },

  cards: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 18 },
  card: { background: PANEL, border: `1px solid ${LINE}`, borderRadius: 12, padding: "18px 20px", boxShadow: "0 1px 2px rgba(16,24,40,0.04)" },
  cardLabel: { fontSize: 11, color: TEXT_MUTED, textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 8 },
  cardValue: { fontSize: 26, fontWeight: 700, color: TEXT },

  summaryBox: {
    background: PANEL_2, border: `1px solid ${LINE}`, borderRadius: 12,
    padding: "14px 18px", fontSize: 13.5, color: TEXT_MUTED, lineHeight: 1.6, marginBottom: 22,
  },

  gaugePanel: {
    display: "flex", gap: 28, alignItems: "center",
    background: PANEL, border: `1px solid ${LINE}`, borderRadius: 12,
    padding: "24px 28px", marginBottom: 24, boxShadow: "0 1px 2px rgba(16,24,40,0.04)",
  },
  gaugeCol: { display: "flex", justifyContent: "center", flexShrink: 0 },
  gaugeDivider: { width: 1, alignSelf: "stretch", background: LINE },
  gaugeStatsCol: { flex: 1, minWidth: 0, textAlign: "left" },
  gaugeStatsTitle: { fontSize: 11, color: TEXT_MUTED, textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 10, fontWeight: 600 },
  gaugeLegend: { display: "flex", flexWrap: "wrap", gap: 18 },

  legendRow: { display: "flex", alignItems: "center", gap: 8, fontSize: 13 },
  legendDot: { width: 9, height: 9, borderRadius: "50%", flexShrink: 0 },
  legendLabel: { color: TEXT },
  legendValue: { color: TEXT_MUTED, fontWeight: 600 },

  categoryGrid: { display: "grid", gap: 12 },
  categoryCard: {
    background: PANEL_2, border: `1px solid ${LINE}`, borderRadius: 10,
    padding: "14px 14px", display: "flex", flexDirection: "column", gap: 6,
  },
  categoryCount: { fontSize: 20, fontWeight: 700, color: TEXT, marginTop: 4 },
  categoryLabel: {
    fontSize: 11.5, color: TEXT_MUTED, lineHeight: 1.3,
    overflow: "hidden", textOverflow: "ellipsis", display: "-webkit-box",
    WebkitLineClamp: 2, WebkitBoxOrient: "vertical",
  },

  tabs: { display: "flex", gap: 0, borderBottom: `1px solid ${LINE}`, marginBottom: 0 },
  tab: {
    background: "none", border: "none", color: TEXT_MUTED, fontSize: 13.5,
    padding: "10px 6px", marginRight: 28, cursor: "pointer",
    borderBottom: "2px solid transparent", fontWeight: 600, fontFamily: FONT,
  },
  tabActive: { color: TEXT, borderBottom: `2px solid ${BLUE}` },

  findingsWrap: { display: "flex", flexDirection: "column", gap: 10, paddingTop: 16 },
  finding: { background: PANEL, borderRadius: 12, border: `1px solid ${LINE}`, overflow: "hidden", boxShadow: "0 1px 2px rgba(16,24,40,0.04)" },
  findingHeader: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    padding: "14px 18px", cursor: "pointer", userSelect: "none",
  },
  findingLeft: { display: "flex", alignItems: "center", gap: 14 },
  sevBadge: {
    fontSize: 11, fontWeight: 700, padding: "3px 10px",
    borderRadius: 6, border: "1px solid", whiteSpace: "nowrap",
  },
  findingTitle: { fontWeight: 600, color: TEXT, fontSize: 14 },
  findingMeta: { fontSize: 12, color: TEXT_MUTED, marginTop: 3 },
  chevron: { color: TEXT_MUTED, fontSize: 16 },
  findingBody: { padding: "0 18px 16px", borderTop: `1px solid ${LINE}` },
  findingSection: { marginTop: 14 },
  findingSectionTitle: { fontSize: 11, color: TEXT_MUTED, textTransform: "uppercase", letterSpacing: 0.6, marginBottom: 6 },
  findingText: { margin: 0, fontSize: 13, color: TEXT, lineHeight: 1.6 },

  rawWrap: { display: "flex", flexDirection: "column", gap: 8, paddingTop: 16 },
  rawLog: { background: PANEL, borderRadius: 10, padding: "12px 16px", border: `1px solid ${LINE}`, fontFamily: "monospace", boxShadow: "0 1px 2px rgba(16,24,40,0.04)" },
  rawLogHeader: { display: "flex", gap: 16, marginBottom: 6, alignItems: "center" },
  rawEventId: { color: BLUE, fontSize: 12, fontWeight: 700 },
  rawMeta: { color: TEXT_MUTED, fontSize: 12 },
  rawLogMsg: { fontSize: 12, color: TEXT_MUTED, lineHeight: 1.5 },

  emptyState: { textAlign: "center", padding: "50px 32px", color: TEXT_MUTED },
  emptyTitle: { fontSize: 16, color: TEXT, marginBottom: 6 },
  emptyStateMain: { textAlign: "center", padding: "90px 32px" },
  emptyMainTitle: { fontSize: 18, color: TEXT, marginBottom: 8, fontWeight: 600 },
  emptyBody: { fontSize: 14, color: TEXT_MUTED },
};