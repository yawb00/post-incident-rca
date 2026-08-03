# Post-Incident Root Cause Analysis Report

**Incident ID:** INC-2026-001
**Report generated:** 2026-08-02 19:28
**Classification:** Phishing-initiated intrusion with lateral movement
**Severity:** High

## Executive Summary
A phishing email bypassed email filtering due to an outdated rule, leading to credential theft, malicious PowerShell execution, and lateral movement to a file server. Detection was delayed by an overly conservative EDR alert threshold, and triage was delayed further by analyst backlog, breaching the response SLA by over 86 minutes. The incident was contained and eradicated within approximately 5 hours of initial access.

## Key Metrics
- **Time to Detect (TTD):** 0:10:34
- **Time to Triage (alert -> analyst review):** 2:18:42
- **Time to Contain (from initial access):** 2:39:57
- **Time to Recover (from initial access):** 6:47:57

## Incident Timeline
| Time (UTC) | Elapsed | Source | Event | Detail |
|---|---|---|---|---|
| 08:12:03 | 0:00:00 | Email Gateway | Email delivered | Phishing email from spoofed domain delivered to jdoe@corp.local. SPF=softfail, not blocked (filter rule outdated). |
| 08:14:41 | 0:02:38 | Endpoint | User click | User clicked link to lookalike login page. |
| 08:14:55 | 0:02:52 | Endpoint | Credential entry | Credentials submitted to external domain. No DLP rule for this pattern. |
| 08:16:10 | 0:04:07 | EDR | Process execution | powershell.exe spawned with encoded command. Alert threshold too high, no alert fired. |
| 08:16:12 | 0:04:09 | EDR | Network connection | Outbound connection to unrecognized external IP on port 443. |
| 08:22:37 | 0:10:34 | SIEM | Correlation alert | Low-priority alert generated, routed to triage queue with 4-hour SLA. |
| 09:05:00 | 0:52:57 | EDR | Lateral movement | SMB authentication from workstation to file server using stolen credentials. |
| 10:41:19 | 2:29:16 | SOC Analyst | Manual triage | Alert reviewed 86 minutes after SLA breach due to 40+ item backlog. Escalated to IR. |
| 10:52:00 | 2:39:57 | IR Team | Containment | Affected hosts isolated from network. |
| 13:15:00 | 5:02:57 | IR Team | Eradication | Malicious artifacts removed, hosts reimaged. |
| 15:00:00 | 6:47:57 | IR Team | Recovery | Hosts validated and returned to production. |

## Root Cause Analysis (5 Whys)

### Initial Access
**What happened:** Phishing email was delivered and not blocked.

- Why did the attacker gain access? -> User clicked a phishing link and submitted credentials.
- Why did the phishing email reach the user? -> Email gateway did not block it (SPF softfail, not blocked).
- Why wasn't it blocked despite the SPF failure? -> The filtering rule was outdated.
- Why was the filtering rule outdated? -> No process to review/update filter rules on a schedule.
- Root cause: Lack of a recurring email filter rule review process.

### Detection Delay
**What happened:** Malicious PowerShell execution did not trigger an alert.

- Why wasn't the malicious process flagged immediately? -> EDR alert threshold was set too high.
- Why was the threshold set too high? -> Tuned previously to reduce alert fatigue from false positives.
- Why did that tuning go unreviewed? -> No periodic detection rule validation process.
- Root cause: Detection rules tuned for noise reduction without a periodic re-validation process against real TTPs.

### Response Delay
**What happened:** 86-minute delay between SLA breach and analyst triage.

- Why was the alert not triaged within SLA? -> Analyst had a backlog of 40+ open alerts.
- Why was the backlog that large? -> Insufficient staffing/alert volume ratio during that shift.
- Why wasn't this caught earlier? -> No real-time SLA breach escalation/alerting mechanism.
- Root cause: No automated SLA breach escalation combined with analyst-to-alert-volume imbalance.

## What Worked Well
- EDR correctly logged network connections and lateral movement, providing full visibility once investigated.
- Containment and eradication, once triggered, were executed efficiently (~2.5 hours from containment to eradication).

## Corrective and Preventive Actions
| Finding | Corrective Action | Owner | Priority |
|---|---|---|---|
| Outdated email filter rules allowed phishing delivery | Implement monthly email filter rule review and threat intel feed integration | Email Security Team | High |
| EDR alert threshold too high, missed malicious PowerShell execution | Re-tune EDR detection rules and validate against MITRE ATT&CK T1059 using atomic tests | Detection Engineering | High |
| 86-minute SLA breach before triage due to alert backlog | Implement automated SLA breach escalation and review analyst staffing vs. alert volume | SOC Manager | Medium |

## Conclusion
This incident highlights that technical controls without process discipline still create risk: the email filter, EDR, and SIEM all functioned as designed, but outdated tuning and staffing gaps delayed detection and response. Implementing the corrective actions above directly addresses each identified root cause rather than the symptom.