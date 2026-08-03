# CY376 Blue Team Project: Post-Incident Root Cause Analysis (RCA) System

**Name:** [Your Name]
**Index Number:** [Your Index Number]
**Course:** CY376 - Network Monitoring, Security and Auditing
**Track:** Blue Team
**Date:** August 2026

## Overview

This project implements a working Post-Incident Root Cause Analysis (RCA) system for a
Security Operations Center (SOC) context. It ingests structured incident data (logs from
simulated SIEM/EDR/email gateway sources), reconstructs an incident timeline, performs
structured 5 Whys root cause analysis, calculates key response metrics, tracks corrective
actions through to closure, and aggregates root cause trends across multiple incidents to
support lessons-learned reporting and organizational learning.

The system addresses a common SOC maturity gap: incidents are often closed after
containment without a structured process to trace root causes back to systemic gaps
(process, technical, or people-related) or to track whether corrective actions are ever
actually completed.

## Problem This Solves

Without a structured RCA process, SOC teams tend to:
- Fix symptoms (e.g., remove malware) without addressing root causes (e.g., outdated
  detection rules, unpatched systems, understaffed triage)
- Lose institutional knowledge between incidents
- Repeat the same root causes across multiple incidents without noticing the pattern

This system enforces structure at each of those failure points.

## Tools and Technologies Used

| Tool | Purpose |
|---|---|
| Python 3.13 | Core application logic |
| Flask | Web application framework serving the live dashboard |
| JSON | Structured incident data storage (simulating SIEM/EDR export format) |
| Git / GitHub | Version control |
| MITRE ATT&CK | Referenced for technique classification (e.g., T1059 PowerShell execution) |
| 5 Whys methodology | Structured root cause analysis technique |

## How to Run

1. Ensure Python 3.10+ is installed: `python --version`
2. Install Flask: `pip install flask`
3. From the project root, run the application:
   `python app.py`
4. Open a browser to: `http://127.0.0.1:5000`
5. Navigate between the Incidents list and the Trends page using the top navigation bar

### Running the standalone analysis scripts (alternative to the web app)

The `src/` folder also contains standalone scripts that demonstrate the same logic
outside the web app, generating a Markdown report instead:

`cd src`
`python report_generator.py`

Output is written to `output/incident_2026_001_RCA.md`.

## Project Structure
## Features

1. **Multi-incident support** - Incidents are loaded dynamically from the
   `data/incidents/` folder. Adding a new incident requires only dropping in a new
   JSON file; no code changes are needed.
2. **Severity-based RCA trigger logic** - The system flags whether an incident meets
   policy threshold for a mandatory RCA (High/Medium severity), mirroring a real SOC
   escalation policy rather than treating RCA as manually optional.
3. **Automated timeline reconstruction** - Raw, potentially out-of-order log entries
   from multiple sources are sorted chronologically and annotated with elapsed time
   since initial access, supporting MTTD/MTTR-style analysis.
4. **5 Whys structured root cause analysis** - Each identified failure point (e.g.,
   detection gap, response delay) is traced through a documented causal chain to a
   systemic root cause, rather than stopping at the surface-level symptom.
5. **Corrective action tracking** - Each root cause maps to a corrective action with
   an owner, priority, and status (Open / In Progress / Closed), closing the loop
   between analysis and remediation.
6. **Cross-incident trends page** - Aggregates root cause categories and action
   statuses across all incidents on record, surfacing recurring systemic issues that
   a single-incident view would miss - the core "organizational learning" goal of a
   mature RCA program.

## Sample Incidents Included

- **INC-2026-001**: Phishing email bypasses an outdated filter rule, leading to
  credential theft, undetected PowerShell execution (EDR threshold too high), and
  lateral movement, with an 86-minute SLA breach during triage.
- **INC-2026-002**: A public-facing server is exploited via a known CVE that had
  been unpatched for 47 days; detected and contained faster due to better SLA
  adherence, but reveals a patch management process gap.

## Key Design Decisions

- **JSON over a database**: chosen for transparency and portability within course
  time constraints; the data model is intentionally structured so it could be
  migrated to a database (e.g., SQLite/Postgres) without changing the analysis logic.
- **Flask over static HTML export**: a running application with routes demonstrates
  the system dynamically loading and processing data, rather than presenting a
  pre-generated, static snapshot.
- **Modular script design**: `timeline_builder.py`, `rca_analyzer.py`, and
  `report_generator.py` are separated and import from one another, demonstrating
  reusable logic rather than one monolithic script.

## Limitations and Future Work

This is a working prototype built to demonstrate the RCA methodology and system
design within a one-month course project. A production version would extend it with:
- Real SIEM/EDR API integration instead of static JSON incident exports
- A persistent database instead of flat files
- Automated root-cause classification (e.g., via log tagging or ML-based
  clustering) instead of manually authored 5 Whys chains
- Role-based access control and audit logging for corrective action updates
- Integration with a ticketing system (e.g., Jira) for corrective action tracking

## Screenshots

See the `evidence/` folder for screenshots of the running system, including the
incident list, incident detail view, and trends page.
