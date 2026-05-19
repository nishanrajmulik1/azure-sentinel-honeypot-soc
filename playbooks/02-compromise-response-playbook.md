# Incident Response Playbook: Successful Compromise After Brute Force

## Overview
- **Detection Rule:** Honeypot - Successful Logon After Brute Force
- **MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts), T1021.001 (Remote Services: RDP)
- **Severity:** Critical
- **Trigger Logic:** A successful logon (Event ID 4624) from an IP that had 10+ failed authentication attempts (Event ID 4625) in the previous hour
- **Response Window:** Immediate (< 15 minutes from alert)

> **This is a confirmed compromise event.** Treat as active incident. Do not wait for further analysis before initiating containment.

## Triggering Conditions
- Successful network or RDP logon (LogonType 3 or 10) following a sustained failed-logon pattern from the same source IP
- Source IP is non-private (not RFC1918)
- The same account was targeted in the brute-force phase

## Detection Phase

### 1. Confirm the incident
- Open the incident in Sentinel → verify it is not a duplicate
- Note: incident number, exact timestamp of successful logon, source IP, compromised account
- Capture the full alert details as evidence (screenshot or export)

### 2. Pivot to raw events to confirm scope

Retrieve all activity from the source IP across the past 24 hours:

```kql
SecurityEvent
| where IpAddress == "<attacker_ip>"
| where TimeGenerated > ago(24h)
| project TimeGenerated, EventID, Account, Activity, LogonType, Computer
| order by TimeGenerated asc
```

Identify the successful logon timestamp — this is your **T-zero** for the compromise timeline.

### 3. Confirm what the attacker did post-logon

```kql
SecurityEvent
| where Account == "<compromised_account>"
| where TimeGenerated > ago(24h)
| where EventID in (4624, 4634, 4672, 4688, 4720, 4724, 4732, 7045)
| project TimeGenerated, EventID, Activity, Computer, ProcessName
| order by TimeGenerated asc
```

Key Event IDs to look for post-compromise:
- **4688** — New process created (what did they run?)
- **4720** — New user account created (persistence)
- **4724** — Password reset attempted (privilege escalation)
- **4732** — User added to security-enabled group (privilege escalation)
- **7045** — New service installed (persistence)

## Triage Questions
- How long between successful logon and current time? (longer = more damage potential)
- Did the attacker create new accounts or modify existing ones?
- Were any privileged groups modified (Administrators, Remote Desktop Users)?
- Are there process executions consistent with attacker tooling (PowerShell, PsExec, Mimikatz)?
- Did outbound network connections originate from the compromised host?
- Is this host connected to other domain resources (file shares, domain controllers)?

## Containment Actions

### Immediate (within 5 minutes)

1. **Isolate the VM at the network layer**
   - Azure Portal → VM → Networking → modify NSG to deny ALL inbound and outbound traffic
   - Or move the VM to a quarantine VNet with no internet access
   - **Do NOT shut down the VM** — preserves memory for forensics

2. **Disable the compromised account**
   - If local: log into VM via Azure Bastion (out-of-band) → disable account in `lusrmgr.msc`
   - If domain: disable in Entra ID / Active Directory immediately

3. **Block the source IP at perimeter**
   - Add to NSG deny rules across all internet-facing resources
   - Submit to threat intelligence watchlist for org-wide block

### Within 15 minutes

4. **Preserve evidence**
   - Take a VM snapshot (do NOT delete the disk) — preserves the disk state at compromise time
   - Capture memory if possible (Azure Disk Snapshot of the VHD)
   - Export all SecurityEvent logs from the past 7 days for the VM to long-term storage

5. **Notify**
   - Page the on-call SOC lead
   - Notify management per your incident response plan
   - If customer data may be involved, engage Legal and Privacy teams immediately

## Investigation Phase

### Process execution analysis

```kql
SecurityEvent
| where Computer == "<vm_name>"
| where EventID == 4688
| where TimeGenerated > ago(24h)
| project TimeGenerated, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated asc
```

Look for suspicious indicators:
- PowerShell with encoded commands (`-EncodedCommand`, `-enc`)
- Living-off-the-land tools (`certutil`, `bitsadmin`, `mshta`, `regsvr32`)
- Credential dumping tools (`mimikatz`, `procdump lsass`)
- Persistence tools (`schtasks`, `sc create`, `reg add Run`)

### Outbound network analysis

```kql
SecurityEvent
| where Computer == "<vm_name>"
| where EventID == 5156
| where TimeGenerated > ago(24h)
| project TimeGenerated, DestAddress, DestPort, Application
| order by TimeGenerated asc
```

Look for:
- Connections to known C2 infrastructure
- Unusual outbound ports (4444, 8080, 8443 for known C2 frameworks)
- DNS lookups to dynamic DNS providers (no-ip, duckdns)

### Persistence enumeration

Connect via Azure Bastion (not RDP — RDP is the attack vector) and check:
- New user accounts (`net user`)
- Scheduled tasks (`schtasks /query`)
- New services (`Get-Service | Where-Object {$_.StartType -eq 'Automatic'}`)
- Run keys in registry (`Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`)
- Modified startup folders

## Eradication

1. **Do NOT attempt to clean the VM.** Once compromised, you cannot trust the host.
2. **Document all indicators of compromise (IOCs):**
   - Source IPs
   - Compromised credentials
   - File hashes from any dropped binaries
   - C2 domains/IPs from outbound traffic
3. **Add all IOCs to the threat intelligence watchlist** in Sentinel
4. **Hunt for the same IOCs across the entire environment:**

```kql
SecurityEvent
| where IpAddress in ("<ioc_ip_1>", "<ioc_ip_2>")
| where TimeGenerated > ago(30d)
| summarize count() by Computer, Account
```

## Recovery

1. **Rebuild the VM from a clean Azure Marketplace image** — never restore from a snapshot taken after the compromise
2. **Reset credentials for ALL accounts** that existed on the compromised host (not just the one used for entry)
3. **Force MFA registration** for all accounts post-rebuild
4. **Apply hardening before re-exposing:**
   - Restrict RDP to specific source IPs or use Azure Bastion only
   - Enable just-in-time (JIT) VM access via Defender for Cloud
   - Enforce strong passwords (16+ chars) and account lockout policies
5. **Validate logging is restored** on the new VM (AMA installed, DCR bound, SecurityEvent flowing)

## Lessons Learned

Document after every Critical incident:

- **Time to detect:** Brute force pattern start → alert fired
- **Time to respond:** Alert fired → VM isolated
- **Time to recover:** Compromise → rebuild complete
- **Detection rule effectiveness:** Did Rule 2 fire correctly?
- **Was the password policy adequate?**
- **Could MFA have prevented this?** (Almost always: yes)
- **What controls failed?** (Network exposure, password strength, account lockout, MFA)

## Mapping to ACSC Essential Eight

| Control | Status in this scenario |
|---|---|
| Multi-factor authentication | **MISSING** — would have prevented compromise entirely |
| Restrict administrative privileges | **PARTIAL** — admin account exposed externally |
| Patch operating systems | N/A — not an exploitation-based attack |
| Application control | **MISSING** — could have blocked attacker tooling post-entry |
| Restrict Microsoft Office macros | N/A |
| User application hardening | N/A |
| Configure Microsoft Office macros | N/A |
| Regular backups | Critical — needed for VM rebuild |

## Post-Incident Reporting

Within 48 hours of incident closure, produce:

1. **Executive summary** — what happened, business impact, current status
2. **Timeline** — minute-by-minute from first failed logon to current state
3. **IOCs** — all attacker artefacts for sharing with threat intel partners
4. **Recommended preventative controls** — mapped to Essential Eight
5. **Detection rule improvements** — what could have caught this earlier