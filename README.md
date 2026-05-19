# Azure Sentinel SOC Honeypot: Detection Engineering & Threat Analysis

> A Windows 10 virtual machine deliberately exposed to the public internet on Microsoft Azure, with all Security events shipped to Microsoft Sentinel. Over approximately 72 hours, the honeypot captured **297,534 failed authentication attempts** from **28 unique IPs** across **14 countries** — including a single US-based IP responsible for one-third of all observed traffic.

![Honeypot Attack Map](screenshots/crop/attack-map-world-crop.png)

---

## Project Summary

- **Goal:** Build an end-to-end SOC capability log collection, detection rules, geographic visualisation, and incident response from scratch on a single laptop.
- **Region:** Australia East (data residency)
- **Exposure window:** ~72 hours
- **Result:** 297,534 attacks captured, 39 incidents auto-generated, 0 successful compromises.

## Architecture

| Layer | Tech |
|---|---|
| Honeypot VM | Windows 10 Pro 22H2 (Standard_B2s) |
| Log Collection | Azure Monitor Agent (AMA) via Data Collection Rule |
| Log Storage | Azure Log Analytics Workspace |
| SIEM | Microsoft Sentinel |
| Query Language | Kusto Query Language (KQL) |
| Threat Mapping | MITRE ATT&CK Framework |
| Geolocation | `geo_info_from_ip_address()` built-in KQL function |

## Headline Numbers

| Metric | Value |
|---|---|
| Failed logon attempts captured | **297,534** |
| Unique attacker IPs | **28** |
| Source countries | **14** |
| Time from exposure to first attack | **~20 hours** |
| Custom detection rules deployed | **5** |
| Incidents auto-generated | **39** |
| Successful unauthorized logons | **0** |

## Top 5 Attacker Countries

| Country | Attempts |
|---|---|
| 🇺🇸 United States | 99,076 |
| 🇺🇦 Ukraine | 69,910 |
| 🇧🇩 Bangladesh | 30,699 |
| 🇷🇴 Romania | 27,677 |
| 🇲🇾 Malaysia | 14,838 |

## Top 5 Most Aggressive IPs

| IP | Country | Attempts |
|---|---|---|
| 20.119.34.7 | United States | 99,068 |
| 119.148.8.66 | Bangladesh | 30,699 |
| 80.94.95.83 | Romania | 27,671 |
| 165.99.199.134 | Malaysia | 14,838 |
| 138.94.140.190 | Mexico | 14,401 |

> **Notable:** A single US-based IP (20.119.34.7) accounted for **33.3% of all attack traffic** — suggesting persistent, dedicated attacker infrastructure rather than opportunistic botnet activity.

## Top 5 Targeted Usernames

![Top Targeted Usernames](screenshots/crop/top-usernames-chart-crop.png)

| Username | Attempts |
|---|---|
| \HONEYPOT | 144,605 |
| \ADMINISTRATOR | 28,227 |
| \USER | 15,236 |
| \ADMIN | 6,026 |
| \BACKUP | 4,952 |

> **Key finding:** Attackers used the VM's hostname (`honeypot-win10`) as a guessed username 144,605 times, almost half of all attempts. The VM's name itself became attack-surface information.

## Detection Rules Built

![Incidents Queue](screenshots/crop/incidents-queue-crop.png)

| # | Rule | MITRE ATT&CK | Severity | Result |
|---|---|---|---|---|
| 1 | RDP Brute Force from Single IP | T1110.001 | Medium | Fired (after tuning, see Lessons Learned) |
| 2 | Successful Logon After Brute Force | T1110 + T1078 | High | Did not fire (no compromise) |
| 3 | Successful Logon from Unusual Country | T1078 | High | Did not fire (no compromise) |
| 4 | Password Spray Detection | T1110.003 | Medium | 27 incidents generated |
| 5 | Distributed Brute Force on Single Account | T1110 | High | Fired after threshold tuning |

## Repository Structure

```
azure-sentinel-honeypot-soc/
├── README.md                          (this file)
├── architecture/                      (diagrams, design docs)
├── kql-queries/                       (analysis queries)
├── detection-rules/                   (5 Sentinel rules + MITRE mapping)
├── playbooks/                         (incident response procedures)
├── reports/                           (final analysis writeup)
├── screenshots/                       (evidence and visualisations)
└── notes/                             (daily progress log)
```

## Key Lessons Learned

### 1. LogonType 3 vs 10 - A Detection Engineering Insight

Initial detection rules filtered for `LogonType == 10` (RemoteInteractive, full RDP session). Analysis of 297,534 failed logon events showed **100% of attacks logged as LogonType 3 (Network)**, none as LogonType 10. Modern RDP brute-force tools fail at Network Level Authentication (NLA) before Windows establishes a RemoteInteractive session. **Production detection rules must include LogonType 3 to capture the true attack pattern.**

### 2. Hostname Leakage as Reconnaissance Risk

48% of all attempts targeted `\HONEYPOT`, derived from the VM's hostname. Production VMs should use non-descriptive hostnames (e.g., `web-prd-04`) to avoid leaking purpose to attackers via RDP banners, certificate CNs, or network broadcasts.

### 3. Single-IP Persistence vs Botnet Spread

A single IP (`20.119.34.7`, US-based) generated 33% of attack traffic. Most threat models assume distributed botnet activity, but dedicated attacker infrastructure is also common. Rate-limiting plus IP-level anomaly detection are complementary controls.

### 4. The Sentinel Connector vs Generic DCR Pitfall

The `SecurityEvent` table is populated only when the Data Collection Rule is created via the **Windows Security Events via AMA** connector page in Sentinel — *not* via the generic Monitor → Data Collection Rules path. Generic DCRs populate the `Event` table instead, which does not trigger Sentinel's built-in detections. This is poorly documented and has taken a lot of troubleshooting time. See `reports/final-analysis-report.md` for full details.

### 5. The Value of Empty Rules

Rules 2 and 3 (compromise indicators) never fired during the observation period, and that is the desired outcome. A detection rule that *doesn't* fire because no compromise occurred is a valuable signal. Detection engineering measures both signal and silence.

## Mapping to ACSC Essential Eight

| Control | How this lab demonstrates it |
|---|---|
| Multi-factor authentication | Would have defeated 100% of observed attacks |
| Restrict admin privileges | The `\ADMINISTRATOR` account saw 28,227 attempts, should never be exposed externally |
| Patch operating systems | Windows 10 22H2 received patches during exposure; AMA-based monitoring continued |
| Application control | Would mitigate post-compromise activity if breach had occurred |

## Tools & Technologies

`Microsoft Azure` · `Microsoft Sentinel` · `Log Analytics` · `KQL` · `Azure Monitor Agent` · `MITRE ATT&CK` · `ACSC Essential Eight` · `Windows Security Event Logging`

## Author

Built by **Nishan Rajmulik** as a self-directed SOC analyst learning project.
Open to roles in detection engineering, SOC analyst (T1/T2), and security operations.

🔗 [GitHub](https://github.com/nishanrajmulik1)
