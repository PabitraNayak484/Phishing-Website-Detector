import json
from datetime import datetime
from urllib.parse import urlparse

import plotly.graph_objects as go
import streamlit as st

from detector import analyze_website

st.set_page_config(
    page_title="AI Phishing Detector",
    page_icon="🛡️",
    layout="wide",
)

# -------------------- Theme / CSS --------------------
st.markdown(
    """
<style>

.hero {
    padding: 30px;
    border-radius: 20px;
    background: linear-gradient(135deg, #0f172a, #1e293b);
    text-align: center;
    margin-bottom: 20px;
    border: 1px solid rgba(255,255,255,0.08);
}

.hero h1 {
    color: white;
    margin-bottom: 8px;
}

.hero p {
    color: #94a3b8;
    margin: 0;
    font-size: 16px;
}

.card {
    background: rgba(255,255,255,0.06);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255,255,255,0.10);
    padding: 20px;
    border-radius: 16px;
    text-align: center;
    box-shadow: 0 0 10px rgba(0,255,157,0.10);
    min-height: 120px;
}

.card h4 {
    margin: 0;
    font-size: 14px;
    color: #cbd5e1;
}

.card h2 {
    margin: 10px 0 0 0;
    font-size: 26px;
    color: white;
    overflow-wrap: anywhere;
}

.signal-box {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.08);
    padding: 14px 16px;
    border-radius: 12px;
    margin-bottom: 10px;
    color: #e2e8f0;
}
</style>
""",
    unsafe_allow_html=True,
)

# -------------------- Session State --------------------
if "history" not in st.session_state:
    st.session_state.history = []

# -------------------- Helpers --------------------
def card(title, value):
    st.markdown(
        f"""
        <div class="card">
            <h4>{title}</h4>
            <h2>{value}</h2>
        </div>
        """,
        unsafe_allow_html=True,
    )


def verdict_from_score(score: int) -> tuple[str, str]:
    if score <= 30:
        return "SAFE", "#22c55e"
    if score <= 60:
        return "SUSPICIOUS", "#facc15"
    return "DANGEROUS", "#ef4444"


def signal_chip(text: str, icon: str):
    st.markdown(
        f'<div class="signal-box">{icon} {text}</div>',
        unsafe_allow_html=True,
    )


def get_url_breakdown(raw_url: str) -> dict:
    parsed = urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
    host = parsed.hostname or ""
    subdomains = host.split(".")[:-2] if host.count(".") >= 2 else []
    query_items = len(parsed.query.split("&")) if parsed.query else 0

    return {
        "scheme": parsed.scheme or "http",
        "hostname": host,
        "subdomains": len(subdomains),
        "path_length": len(parsed.path or ""),
        "query_items": query_items,
        "has_query": bool(parsed.query),
        "port": parsed.port,
    }


def build_report_text(url: str, result: dict, verdict: str, scan_time: str, breakdown: dict) -> str:
    lines = [
        "Phishing Website Detector Report",
        "",
        f"Scan Time: {scan_time}",
        f"Input URL: {url}",
        f"Normalized URL: {result['normalized_url']}",
        f"Hostname: {result['hostname']}",
        f"Final URL: {result['final_url']}",
        f"Status Code: {result['status_code']}",
        f"Reachable: {result['reachable']}",
        f"Risk Score: {result['risk_score']}/100",
        f"Verdict: {verdict}",
        "",
        "URL Breakdown:",
        f"- Scheme: {breakdown['scheme']}",
        f"- Subdomains: {breakdown['subdomains']}",
        f"- Path length: {breakdown['path_length']}",
        f"- Query items: {breakdown['query_items']}",
        "",
        "URL Checks:",
    ]

    for item in result["url_checks"]:
        lines.append(f"- {item}")

    lines.extend(["", "Content Checks:"])
    for item in result["content_checks"]:
        lines.append(f"- {item}")

    lines.extend(["", "Recommendations:"])
    for item in result["recommendations"]:
        lines.append(f"- {item}")

    return "\n".join(lines)


# -------------------- Sidebar --------------------
with st.sidebar:
    st.image(
        "https://cdn-icons-png.flaticon.com/512/2092/2092663.png",
        width=80,
    )
    st.title("Navigation")

    page = st.radio(
        "",
        ["Website Scan", "Threat Intelligence", "History", "About"],
    )

    st.divider()
    st.markdown("### How it works")
    st.write("• URL structure checks")
    st.write("• SSL and domain-age analysis")
    st.write("• Page content and form analysis")
    st.write("• Risk scoring")

    st.divider()
    st.markdown("### Recent scans")
    if st.session_state.history:
        for item in st.session_state.history[-5:][::-1]:
            st.caption(f"{item['time']} • {item['verdict']} • {item['score']}/100")
            st.caption(item["url"])
            st.caption("")
    else:
        st.caption("No scans yet.")

# -------------------- Hero --------------------
st.markdown(
    """
    <div class="hero">
        <h1>🛡️ AI Phishing Website Detector</h1>
        <p>Real-Time Cybersecurity Risk Analysis Dashboard</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# -------------------- Pages --------------------
if page == "About":
    st.subheader("About this project")
    st.write(
        "This project detects suspicious websites using heuristic checks such as "
        "URL structure, suspicious keywords, SSL details, redirects, forms, and page content."
    )
    st.write(
        "It is a strong college cybersecurity project and can be extended with ML, WHOIS, "
        "VirusTotal, browser extension support, or a database."
    )
    st.stop()

if page == "Threat Intelligence":
    st.subheader("Threat Intelligence")
    st.write("Common phishing indicators used in this project:")
    st.write("• Long or strange URL structure")
    st.write("• IP address instead of a real domain")
    st.write("• Shortened URLs")
    st.write("• Suspicious words like login, verify, password, update")
    st.write("• Forms that may collect credentials")
    st.write("• External resources, redirects, and hidden elements")
    st.stop()

if page == "History":
    st.subheader("Scan History")
    if not st.session_state.history:
        st.info("No scan history yet.")
    else:
        for item in reversed(st.session_state.history):
            with st.expander(f"{item['time']} • {item['verdict']} • {item['score']}/100"):
                st.write(f"**URL:** {item['url']}")
                st.write(f"**Hostname:** {item['hostname']}")
                st.write(f"**Status Code:** {item['status_code']}")
                st.write(f"**Reachable:** {item['reachable']}")
                st.write(f"**Issues Found:** {item['issues']}")
    st.stop()

# -------------------- Website Scan --------------------
url = st.text_input(
    "Website URL",
    placeholder="https://example.com",
)

scan_clicked = st.button("🔍 Scan Website", use_container_width=True)

if scan_clicked:
    if not url.strip():
        st.error("Please enter a website URL.")
        st.stop()

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cleaned_url = url.strip()
    breakdown = get_url_breakdown(cleaned_url)

    with st.spinner("Analyzing website..."):
        result = analyze_website(cleaned_url)

    score = result["risk_score"]
    verdict, color = verdict_from_score(score)
    issues_found = len(result["url_checks"]) + len(result["content_checks"])

    st.session_state.history.append(
        {
            "time": scan_time,
            "url": cleaned_url,
            "verdict": verdict,
            "score": score,
            "hostname": result["hostname"],
            "status_code": result["status_code"],
            "reachable": result["reachable"],
            "issues": issues_found,
        }
    )

    st.markdown(
        f"""
        <div style="
            background:{color};
            padding:15px;
            border-radius:12px;
            text-align:center;
            font-size:24px;
            font-weight:bold;
            color:#0f172a;
            margin-top:10px;
            margin-bottom:20px;">
            Website Verdict: {verdict}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("Security Overview")
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        card("Risk Score", f"{score}/100")

    with c2:
        card("Issues Found", str(issues_found))

    with c3:
        card("Domain Age", str(result.get("domain_age_days", "N/A")))

    with c4:
        ssl_status = "✅ Valid" if result.get("ssl_valid") else "❌ Invalid"
        card("SSL", ssl_status)

    st.divider()

    st.subheader("Threat Level")
    gauge = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            title={"text": "Threat Level"},
            gauge={
                "axis": {"range": [0, 100]},
                "steps": [
                    {"range": [0, 30], "color": "green"},
                    {"range": [30, 60], "color": "yellow"},
                    {"range": [60, 100], "color": "red"},
                ],
            },
        )
    )
    st.plotly_chart(gauge, use_container_width=True)

    st.divider()

    st.subheader("URL Breakdown")
    b1, b2, b3, b4 = st.columns(4)

    with b1:
        card("Scheme", breakdown["scheme"].upper())

    with b2:
        card("Subdomains", str(breakdown["subdomains"]))

    with b3:
        card("Path Length", str(breakdown["path_length"]))

    with b4:
        card("Query Items", str(breakdown["query_items"]))

    st.divider()

    tab1, tab2, tab3 = st.tabs(
        ["🔗 URL Analysis", "📄 Content Analysis", "⚙ Technical Details"]
    )

    with tab1:
        st.subheader("URL Analysis")
        for item in result["url_checks"]:
            signal_chip(item, "🔗")

    with tab2:
        st.subheader("Content Analysis")
        for item in result["content_checks"]:
            signal_chip(item, "📄")

    with tab3:
        st.subheader("Technical Details")
        st.json(
            {
                "Scan Time": scan_time,
                "Hostname": result["hostname"],
                "Final URL": result["final_url"],
                "Page Title": result["page_title"],
                "Status Code": result["status_code"],
                "Reachable": result["reachable"],
                "Normalized URL": result["normalized_url"],
                "Domain Age (Days)": result.get("domain_age_days"),
                "SSL Valid": result.get("ssl_valid"),
                "SSL Issuer": result.get("ssl_issuer"),
                "SSL Days Left": result.get("ssl_days_left"),
                "Redirect Count": result.get("redirect_count"),
                "Domain Entropy": result.get("entropy"),
            }
        )

    st.divider()

    st.subheader("Recommendations")
    for rec in result["recommendations"]:
        st.success(rec)

    st.divider()

    report_text = build_report_text(cleaned_url, result, verdict, scan_time, breakdown)
    report_json = json.dumps(
        {
            "scan_time": scan_time,
            "input_url": cleaned_url,
            "normalized_url": result["normalized_url"],
            "hostname": result["hostname"],
            "final_url": result["final_url"],
            "status_code": result["status_code"],
            "reachable": result["reachable"],
            "risk_score": score,
            "verdict": verdict,
            "url_checks": result["url_checks"],
            "content_checks": result["content_checks"],
            "recommendations": result["recommendations"],
            "domain_age_days": result.get("domain_age_days"),
            "ssl_valid": result.get("ssl_valid"),
            "ssl_issuer": result.get("ssl_issuer"),
            "ssl_days_left": result.get("ssl_days_left"),
            "redirect_count": result.get("redirect_count"),
            "entropy": result.get("entropy"),
            "url_breakdown": breakdown,
        },
        indent=2,
    )

    d1, d2 = st.columns(2)
    with d1:
        st.download_button(
            "📥 Download Report (TXT)",
            report_text,
            file_name="security_report.txt",
        )
    with d2:
        st.download_button(
            "📦 Download Report (JSON)",
            report_json,
            file_name="security_report.json",
        )

else:
    st.info("Enter a URL above and click **Scan Website** to begin.")