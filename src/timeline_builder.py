import json
from datetime import datetime

def load_logs(filepath):
    """Load raw incident logs from JSON file."""
    with open(filepath, "r") as f:
        return json.load(f)

def parse_timestamp(ts):
    """Convert ISO timestamp string into a datetime object we can do math on."""
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

def build_timeline(logs):
    """Sort events chronologically and calculate time-since-start for each."""
    # Sort by timestamp, in case logs arrive out of order from different sources
    sorted_logs = sorted(logs, key=lambda x: parse_timestamp(x["timestamp"]))

    start_time = parse_timestamp(sorted_logs[0]["timestamp"])
    timeline = []

    for entry in sorted_logs:
        event_time = parse_timestamp(entry["timestamp"])
        elapsed = event_time - start_time
        timeline.append({
            "timestamp": entry["timestamp"],
            "elapsed": str(elapsed),
            "source": entry["source"],
            "event": entry["event"],
            "detail": entry["detail"]
        })
    return timeline

def print_timeline(timeline):
    """Print a readable timeline to the console."""
    print(f"{'TIME (UTC)':<22}{'ELAPSED':<12}{'SOURCE':<18}{'EVENT'}")
    print("-" * 90)
    for entry in timeline:
        time_only = entry["timestamp"].split("T")[1].replace("Z", "")
        print(f"{time_only:<22}{entry['elapsed']:<12}{entry['source']:<18}{entry['event']}")
        print(f"    -> {entry['detail']}")
    print("-" * 90)

if __name__ == "__main__":
    logs = load_logs("../data/incident_logs.json")
    timeline = build_timeline(logs)
    print_timeline(timeline)