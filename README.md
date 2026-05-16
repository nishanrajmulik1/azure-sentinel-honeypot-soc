# Azure Sentinel Honeypot SOC

Building a cloud SOC: detecting real-world attacks against an internet-exposed Windows honeypot using Microsoft Sentinel and KQL.

**Status:** In progress — Phase 0

## Project Goals

- Deploy a Windows honeypot in Azure exposed to the public internet
- Ingest logs into Microsoft Sentinel via Log Analytics
- Build custom KQL detection rules mapped to MITRE ATT&CK
- Visualise attacker geography and behaviour
- Document incident response playbooks
- Map findings to ACSC Essential Eight controls

## Architecture

*Diagram coming soon*

## Tech Stack

- Microsoft Azure (Australia East region)
- Microsoft Sentinel (SIEM)
- Log Analytics Workspace
- KQL (Kusto Query Language)
- MITRE ATT&CK Framework
- ACSC Essential Eight

## Repository Structure

- `architecture/` — diagrams and design docs
- `kql-queries/` — reusable KQL queries
- `detection-rules/` — Sentinel analytic rules
- `playbooks/` — incident response procedures
- `reports/` — analysis writeups
- `screenshots/` — evidence and visualisations
- `notes/` — daily progress log

## Author

Nishan Rajmulik — Aspiring Cyber Security Analyst
