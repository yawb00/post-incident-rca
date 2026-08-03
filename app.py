from flask import Flask, render_template_string, Response
import json, os
from datetime import datetime
from collections import Counter

app = Flask(__name__)
INCIDENTS_DIR = "data/incidents"

# --- Data loading ---
def load_all_incidents():
    incidents = []
    for f in sorted(os.listdir(INCIDENTS_DIR)):
        if f.endswith(".json"):
            with open(os.path.join(INCIDENTS_DIR, f)) as file:
                incidents.append(json.load(file))
    return incidents

def load_incident(incident_id):
    for inc in load_all_incidents():
        if inc["incident_id"] == incident_id:
            return inc
    return None

def parse_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

def build_timeline(logs):
    sorted_logs = sorted(logs, key=lambda x: parse_ts(x["timestamp"]))
    start = parse_ts(sorted_logs[0]["timestamp"])
    return [{**e, "elapsed": str(parse_ts(e["timestamp"]) - start)} for e in sorted_logs]

def calculate_metrics(timeline):
    by_event = {e["event"]: e for e in timeline}
    start = parse_ts(timeline[0]["timestamp"])
    metrics = {}
    if "Correlation alert" in by_event:
        metrics["Time to Detect"] = str(parse_ts(by_event["Correlation alert"]["timestamp"]) - start)
    if "Manual triage" in by_event and "Correlation alert" in by_event:
        metrics["Time to Triage"] = str(parse_ts(by_event["Manual triage"]["timestamp"]) - parse_ts(by_event["Correlation alert"]["timestamp"]))
    if "Containment" in by_event:
        metrics["Time to Contain"] = str(parse_ts(by_event["Containment"]["timestamp"]) - start)
    if "Recovery" in by_event:
        metrics["Time to Recover"] = str(parse_ts(by_event["Recovery"]["timestamp"]) - start)
    return metrics

# --- Feature: RCA trigger logic ---
def rca_required(severity):
    """Mirrors a real SOC trigger policy: High/Medium severity mandates a full RCA."""
    return severity in ("High", "Medium")

# --- Feature: Markdown report generation ---
def generate_markdown_report(inc, timeline, metrics):
    lines = []
    lines.append(f"# Post-Incident Root Cause Analysis Report")
    lines.append(f"\n**Incident ID:** {inc['incident_id']}")
    lines.append(f"**Classification:** {inc['classification']}")
    lines.append(f"**Severity:** {inc['severity']}\n")

    lines.append("## Key Metrics")
    for k, v in metrics.items():
        lines.append(f"- **{k}:** {v}")
    lines.append("")

    lines.append("## Incident Timeline")
    lines.append("| Time (UTC) | Elapsed | Source | Event | Detail |")
    lines.append("|---|---|---|---|---|")
    for e in timeline:
        time_only = e['timestamp'].split('T')[1].replace('Z', '')
        lines.append(f"| {time_only} | {e['elapsed']} | {e['source']} | {e['event']} | {e['detail']} |")
    lines.append("")

    lines.append("## Root Cause Analysis (5 Whys)")
    for category, data in inc["root_cause_analysis"].items():
        lines.append(f"\n### {category}")
        lines.append(f"**What happened:** {data['what_happened']}\n")
        for line in data["chain"]:
            lines.append(f"- {line}")
    lines.append("")

    lines.append("## Corrective and Preventive Actions")
    lines.append("| Finding | Action | Owner | Priority | Status |")
    lines.append("|---|---|---|---|---|")
    for a in inc["corrective_actions"]:
        lines.append(f"| {a['finding']} | {a['action']} | {a['owner']} | {a['priority']} | {a['status']} |")
    lines.append("")

    if "what_worked_well" in inc:
        lines.append("## What Worked Well")
        for item in inc["what_worked_well"]:
            lines.append(f"- {item}")
        lines.append("")

    if "lessons_learned_meeting" in inc:
        llm = inc["lessons_learned_meeting"]
        lines.append("## Lessons-Learned Meeting")
        lines.append(f"**Date:** {llm['date']}")
        lines.append(f"**Facilitator:** {llm['facilitator']}")
        lines.append(f"**Attendees:** {', '.join(llm['attendees'])}\n")
        lines.append(f"**Key Takeaway:** {llm['key_takeaway']}")

    return "\n".join(lines)

# --- Styling ---
BASE_STYLE = """
<style>
  body { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 30px; }
  h1 { color: #38bdf8; } h2 { color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 8px; }
  h3 { color: #fbbf24; }
  a { color: #38bdf8; text-decoration: none; }
  nav { margin-bottom: 25px; }
  nav a { margin-right: 20px; font-weight: bold; }
  .card { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 15px; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th, td { border: 1px solid #334155; padding: 8px; font-size: 13px; text-align: left; }
  th { background: #1e293b; color: #38bdf8; }
  .metric-value { font-size: 22px; color: #38bdf8; font-weight: bold; }
  .badge { padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; }
  .sev-high { background: #7f1d1d; color: #fca5a5; }
  .sev-medium { background: #78350f; color: #fcd34d; }
  .status-open { background: #7f1d1d; color: #fca5a5; }
  .status-inprogress { background: #78350f; color: #fcd34d; }
  .status-closed { background: #14532d; color: #86efac; }
  .rca-flag { background: #164e63; color: #67e8f9; padding: 8px 12px; border-radius: 6px; display: inline-block; margin: 10px 0; }
  .download-btn { float:right; background:#0284c7; color:white; padding:8px 16px; border-radius:6px; font-weight:bold; }
  .download-btn:hover { background:#0369a1; }
  .worked-well li { color:#86efac; margin-bottom:6px; }
  .llm-card { background:#1e293b; border-left:4px solid #38bdf8; padding:15px 20px; border-radius:8px; }
  .llm-meta { color:#94a3b8; font-size:13px; margin-bottom:10px; }
</style>
"""

def nav():
    return '<nav><a href="/">Incidents</a><a href="/trends">Trends</a></nav>'

# --- Routes ---
@app.route("/")
def index():
    incidents = load_all_incidents()
    cards = ""
    for inc in incidents:
        sev_class = "sev-high" if inc["severity"] == "High" else "sev-medium"
        trigger_note = "RCA Required (policy-triggered)" if rca_required(inc["severity"]) else "RCA Optional"
        cards += f"""
        <div class="card">
            <a href="/incident/{inc['incident_id']}"><h3>{inc['incident_id']}</h3></a>
            <span class="badge {sev_class}">{inc['severity']}</span>
            <p>{inc['classification']}</p>
            <p style="color:#67e8f9; font-size:13px;">{trigger_note}</p>
        </div>"""
    return render_template_string(f"""
    <html><head><title>RCA System</title>{BASE_STYLE}</head>
    <body>{nav()}<h1>Incident RCA Dashboard</h1><p>{len(incidents)} incident(s) on record</p>{cards}</body></html>
    """)

@app.route("/incident/<incident_id>")
def incident_detail(incident_id):
    inc = load_incident(incident_id)
    timeline = build_timeline(inc["logs"])
    metrics = calculate_metrics(timeline)

    metrics_html = "".join(f'<div class="card"><div class="metric-value">{v}</div>{k}</div>' for k, v in metrics.items())
    rows = "".join(
        f"<tr><td>{e['timestamp'].split('T')[1].replace('Z','')}</td><td>{e['elapsed']}</td>"
        f"<td>{e['source']}</td><td>{e['event']}</td><td>{e['detail']}</td></tr>" for e in timeline
    )

    whys_html = ""
    for category, data in inc["root_cause_analysis"].items():
        chain_items = "".join(f"<li>{line}</li>" for line in data["chain"])
        whys_html += f'<div class="card"><h3>{category}</h3><p><em>{data["what_happened"]}</em></p><ul>{chain_items}</ul></div>'

    actions_rows = ""
    for a in inc["corrective_actions"]:
        status_class = "status-" + a["status"].lower().replace(" ", "")
        actions_rows += (f"<tr><td>{a['finding']}</td><td>{a['action']}</td><td>{a['owner']}</td>"
                          f"<td>{a['priority']}</td><td><span class='badge {status_class}'>{a['status']}</span></td></tr>")

    trigger_banner = ""
    if rca_required(inc["severity"]):
        trigger_banner = f'<div class="rca-flag">This incident met policy threshold (Severity: {inc["severity"]}) — full RCA automatically required.</div>'

    worked_well_html = ""
    if "what_worked_well" in inc:
        items = "".join(f"<li>{item}</li>" for item in inc["what_worked_well"])
        worked_well_html = f'<h2>What Worked Well</h2><div class="card"><ul class="worked-well">{items}</ul></div>'

    llm_html = ""
    if "lessons_learned_meeting" in inc:
        llm = inc["lessons_learned_meeting"]
        attendees = ", ".join(llm["attendees"])
        llm_html = f"""
        <h2>Lessons-Learned Meeting</h2>
        <div class="llm-card">
            <div class="llm-meta"><strong>Date:</strong> {llm['date']} &nbsp;|&nbsp; <strong>Facilitator:</strong> {llm['facilitator']}</div>
            <div class="llm-meta"><strong>Attendees:</strong> {attendees}</div>
            <p><strong>Key Takeaway:</strong> {llm['key_takeaway']}</p>
        </div>"""

    return render_template_string(f"""
    <html><head><title>{incident_id}</title>{BASE_STYLE}</head>
    <body>{nav()}
      <a href="/">&larr; Back to all incidents</a>
      <a href="/incident/{incident_id}/report" class="download-btn">Download RCA Report</a>
      <h1>{incident_id}</h1>
      <p>{inc['classification']}</p>
      {trigger_banner}
      <h2>Metrics</h2>
      <div style="display:flex;gap:15px;flex-wrap:wrap;">{metrics_html}</div>
      <h2>Timeline</h2>
      <table><tr><th>Time</th><th>Elapsed</th><th>Source</th><th>Event</th><th>Detail</th></tr>{rows}</table>
      <h2>Root Cause Analysis (5 Whys)</h2>
      {whys_html}
      <h2>Corrective Actions</h2>
      <table><tr><th>Finding</th><th>Action</th><th>Owner</th><th>Priority</th><th>Status</th></tr>{actions_rows}</table>
      {worked_well_html}
      {llm_html}
    </body></html>
    """)

@app.route("/incident/<incident_id>/report")
def download_report(incident_id):
    inc = load_incident(incident_id)
    timeline = build_timeline(inc["logs"])
    metrics = calculate_metrics(timeline)
    report_text = generate_markdown_report(inc, timeline, metrics)

    return Response(
        report_text,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment;filename={incident_id}_RCA_Report.md"}
    )

# --- Trends page ---
@app.route("/trends")
def trends():
    incidents = load_all_incidents()

    root_cause_categories = Counter()
    action_status_counts = Counter()
    severity_counts = Counter()

    for inc in incidents:
        severity_counts[inc["severity"]] += 1
        for category in inc["root_cause_analysis"]:
            root_cause_categories[category] += 1
        for action in inc["corrective_actions"]:
            action_status_counts[action["status"]] += 1

    rc_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in root_cause_categories.items())
    status_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in action_status_counts.items())
    sev_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in severity_counts.items())

    return render_template_string(f"""
    <html><head><title>Trends</title>{BASE_STYLE}</head>
    <body>{nav()}
      <h1>Trends Across {len(incidents)} Incident(s)</h1>
      <div class="card">
        <h2>Incidents by Severity</h2>
        <table><tr><th>Severity</th><th>Count</th></tr>{sev_rows}</table>
      </div>
      <div class="card">
        <h2>Recurring Root Cause Categories</h2>
        <table><tr><th>Category</th><th>Occurrences</th></tr>{rc_rows}</table>
        <p style="color:#94a3b8; font-size:13px;">Categories appearing more than once across incidents indicate a systemic gap, not an isolated failure.</p>
      </div>
      <div class="card">
        <h2>Corrective Action Status</h2>
        <table><tr><th>Status</th><th>Count</th></tr>{status_rows}</table>
      </div>
    </body></html>
    """)

if __name__ == "__main__":
    app.run(debug=True)