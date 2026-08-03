from timeline_builder import load_logs, build_timeline
from rca_analyzer import calculate_metrics, FIVE_WHYS
from report_generator import CORRECTIVE_ACTIONS

def generate_dashboard(timeline, metrics, output_path):
    metrics_html = "".join(
        f'<div class="metric-card"><div class="metric-value">{v}</div><div class="metric-label">{k}</div></div>'
        for k, v in metrics.items()
    )

    timeline_rows = "".join(
        f"<tr><td>{e['timestamp'].split('T')[1].replace('Z','')}</td><td>{e['elapsed']}</td>"
        f"<td>{e['source']}</td><td>{e['event']}</td><td>{e['detail']}</td></tr>"
        for e in timeline
    )

    whys_html = ""
    for category, data in FIVE_WHYS.items():
        chain_items = "".join(f"<li>{line}</li>" for line in data["chain"])
        whys_html += f"""
        <div class="why-block">
            <h3>{category}</h3>
            <p><em>{data['what_happened']}</em></p>
            <ul>{chain_items}</ul>
        </div>"""

    actions_rows = "".join(
        f"<tr><td>{a['finding']}</td><td>{a['action']}</td><td>{a['owner']}</td>"
        f"<td><span class='priority-{a['priority'].lower()}'>{a['priority']}</span></td></tr>"
        for a in CORRECTIVE_ACTIONS
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<title>RCA Dashboard - INC-2026-001</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 30px; }}
  h1 {{ color: #38bdf8; }}
  h2 {{ color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-top: 40px; }}
  h3 {{ color: #fbbf24; }}
  .metrics {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
  .metric-card {{ background: #1e293b; padding: 20px; border-radius: 8px; min-width: 160px; text-align: center; }}
  .metric-value {{ font-size: 24px; font-weight: bold; color: #38bdf8; }}
  .metric-label {{ font-size: 12px; color: #94a3b8; margin-top: 5px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
  th, td {{ border: 1px solid #334155; padding: 8px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #1e293b; color: #38bdf8; }}
  tr:nth-child(even) {{ background: #172033; }}
  .why-block {{ background: #1e293b; padding: 15px 20px; border-radius: 8px; margin-bottom: 15px; }}
  .priority-high {{ color: #f87171; font-weight: bold; }}
  .priority-medium {{ color: #fbbf24; font-weight: bold; }}
</style>
</head>
<body>
  <h1>Post-Incident RCA Dashboard</h1>
  <p><strong>Incident:</strong> INC-2026-001 &nbsp;|&nbsp; <strong>Classification:</strong> Phishing-initiated intrusion &nbsp;|&nbsp; <strong>Severity:</strong> High</p>

  <h2>Key Metrics</h2>
  <div class="metrics">{metrics_html}</div>

  <h2>Incident Timeline</h2>
  <table>
    <tr><th>Time</th><th>Elapsed</th><th>Source</th><th>Event</th><th>Detail</th></tr>
    {timeline_rows}
  </table>

  <h2>Root Cause Analysis (5 Whys)</h2>
  {whys_html}

  <h2>Corrective Actions</h2>
  <table>
    <tr><th>Finding</th><th>Action</th><th>Owner</th><th>Priority</th></tr>
    {actions_rows}
  </table>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"Dashboard written to {output_path}")

if __name__ == "__main__":
    logs = load_logs("../data/incident_logs.json")
    timeline = build_timeline(logs)
    metrics = calculate_metrics(timeline)
    generate_dashboard(timeline, metrics, "../output/dashboard.html")