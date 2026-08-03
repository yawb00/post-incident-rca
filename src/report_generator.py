from datetime import datetime
from timeline_builder import load_logs, build_timeline
from rca_analyzer import calculate_metrics, FIVE_WHYS

CORRECTIVE_ACTIONS = [
    {"finding": "Outdated email filter rules allowed phishing delivery", 
     "action": "Implement monthly email filter rule review and threat intel feed integration",
     "owner": "Email Security Team", "priority": "High"},
    {"finding": "EDR alert threshold too high, missed malicious PowerShell execution", 
     "action": "Re-tune EDR detection rules and validate against MITRE ATT&CK T1059 using atomic tests",
     "owner": "Detection Engineering", "priority": "High"},
    {"finding": "86-minute SLA breach before triage due to alert backlog", 
     "action": "Implement automated SLA breach escalation and review analyst staffing vs. alert volume",
     "owner": "SOC Manager", "priority": "Medium"},
]

def generate_report(timeline, metrics, output_path):
    lines = []
    lines.append("# Post-Incident Root Cause Analysis Report")
    lines.append(f"\n**Incident ID:** INC-2026-001")
    lines.append(f"**Report generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"**Classification:** Phishing-initiated intrusion with lateral movement")
    lines.append(f"**Severity:** High\n")

    lines.append("## Executive Summary")
    lines.append(
        "A phishing email bypassed email filtering due to an outdated rule, leading to credential "
        "theft, malicious PowerShell execution, and lateral movement to a file server. Detection was "
        "delayed by an overly conservative EDR alert threshold, and triage was delayed further by "
        "analyst backlog, breaching the response SLA by over 86 minutes. The incident was contained "
        "and eradicated within approximately 5 hours of initial access.\n"
    )

    lines.append("## Key Metrics")
    for k, v in metrics.items():
        lines.append(f"- **{k}:** {v}")
    lines.append("")

    lines.append("## Incident Timeline")
    lines.append("| Time (UTC) | Elapsed | Source | Event | Detail |")
    lines.append("|---|---|---|---|---|")
    for entry in timeline:
        time_only = entry["timestamp"].split("T")[1].replace("Z", "")
        lines.append(f"| {time_only} | {entry['elapsed']} | {entry['source']} | {entry['event']} | {entry['detail']} |")
    lines.append("")

    lines.append("## Root Cause Analysis (5 Whys)")
    for category, data in FIVE_WHYS.items():
        lines.append(f"\n### {category}")
        lines.append(f"**What happened:** {data['what_happened']}\n")
        for line in data["chain"]:
            lines.append(f"- {line}")
    lines.append("")

    lines.append("## What Worked Well")
    lines.append("- EDR correctly logged network connections and lateral movement, providing full visibility once investigated.")
    lines.append("- Containment and eradication, once triggered, were executed efficiently (~2.5 hours from containment to eradication).\n")

    lines.append("## Corrective and Preventive Actions")
    lines.append("| Finding | Corrective Action | Owner | Priority |")
    lines.append("|---|---|---|---|")
    for item in CORRECTIVE_ACTIONS:
        lines.append(f"| {item['finding']} | {item['action']} | {item['owner']} | {item['priority']} |")
    lines.append("")

    lines.append("## Conclusion")
    lines.append(
        "This incident highlights that technical controls without process discipline still create risk: "
        "the email filter, EDR, and SIEM all functioned as designed, but outdated tuning and staffing gaps "
        "delayed detection and response. Implementing the corrective actions above directly addresses each "
        "identified root cause rather than the symptom."
    )

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    print(f"Report written to {output_path}")

if __name__ == "__main__":
    logs = load_logs("../data/incident_logs.json")
    timeline = build_timeline(logs)
    metrics = calculate_metrics(timeline)
    generate_report(timeline, metrics, "../output/incident_2026_001_RCA.md")