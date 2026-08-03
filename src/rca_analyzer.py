from datetime import datetime
from timeline_builder import load_logs, build_timeline, parse_timestamp

# --- 5 Whys chains, mapped to what we saw in the timeline ---
FIVE_WHYS = {
    "Initial Access": {
        "what_happened": "Phishing email was delivered and not blocked.",
        "chain": [
            "Why did the attacker gain access? -> User clicked a phishing link and submitted credentials.",
            "Why did the phishing email reach the user? -> Email gateway did not block it (SPF softfail, not blocked).",
            "Why wasn't it blocked despite the SPF failure? -> The filtering rule was outdated.",
            "Why was the filtering rule outdated? -> No process to review/update filter rules on a schedule.",
            "Root cause: Lack of a recurring email filter rule review process."
        ]
    },
    "Detection Delay": {
        "what_happened": "Malicious PowerShell execution did not trigger an alert.",
        "chain": [
            "Why wasn't the malicious process flagged immediately? -> EDR alert threshold was set too high.",
            "Why was the threshold set too high? -> Tuned previously to reduce alert fatigue from false positives.",
            "Why did that tuning go unreviewed? -> No periodic detection rule validation process.",
            "Root cause: Detection rules tuned for noise reduction without a periodic re-validation process against real TTPs."
        ]
    },
    "Response Delay": {
        "what_happened": "86-minute delay between SLA breach and analyst triage.",
        "chain": [
            "Why was the alert not triaged within SLA? -> Analyst had a backlog of 40+ open alerts.",
            "Why was the backlog that large? -> Insufficient staffing/alert volume ratio during that shift.",
            "Why wasn't this caught earlier? -> No real-time SLA breach escalation/alerting mechanism.",
            "Root cause: No automated SLA breach escalation combined with analyst-to-alert-volume imbalance."
        ]
    }
}

def calculate_metrics(timeline):
    """Calculate key incident response time metrics."""
    events_by_type = {e["event"]: e for e in timeline}

    detection_time = parse_timestamp(events_by_type["Correlation alert"]["timestamp"])
    initial_access_time = parse_timestamp(timeline[0]["timestamp"])
    triage_time = parse_timestamp(events_by_type["Manual triage"]["timestamp"])
    containment_time = parse_timestamp(events_by_type["Containment"]["timestamp"])
    recovery_time = parse_timestamp(events_by_type["Recovery"]["timestamp"])

    return {
        "Time to Detect (TTD)": str(detection_time - initial_access_time),
        "Time to Triage (alert -> analyst review)": str(triage_time - detection_time),
        "Time to Contain (from initial access)": str(containment_time - initial_access_time),
        "Time to Recover (from initial access)": str(recovery_time - initial_access_time),
    }

def print_analysis(metrics):
    print("=== KEY METRICS ===")
    for k, v in metrics.items():
        print(f"{k}: {v}")

    print("\n=== 5 WHYS ROOT CAUSE ANALYSIS ===")
    for category, data in FIVE_WHYS.items():
        print(f"\n--- {category} ---")
        print(f"What happened: {data['what_happened']}")
        for line in data["chain"]:
            print(f"  {line}")

if __name__ == "__main__":
    logs = load_logs("../data/incident_logs.json")
    timeline = build_timeline(logs)
    metrics = calculate_metrics(timeline)
    print_analysis(metrics)