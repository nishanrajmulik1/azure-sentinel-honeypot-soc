# Incident Response Playbook: RDP Brute Force Attack

## Overview
- **Detection Rule:** Honeypot - RDP Brute Force from Single IP
- **MITRE ATT&CK:** T1110.001 (Password Guessing), T1021.001 (Remote Services: RDP)
- **Severity:** Medium (Critical if successful logon follows)
- **Average Frequency:** Multiple per hour for any internet-exposed RDP

## Triggering Conditions
- 20+ failed RDP logons (EventID 4625, LogonType 10) from a single source IP within 10 minutes
- Source IP is non-private (not RFC1918)

## Detection Phase
1. **Confirm the incident in Sentinel Incidents queue**
   - Verify the alert is not a duplicate of an existing investigation
   - Note the incident number, severity, and timestamp
2. **Review entity data**
   - Source IP, targeted account(s), attempt count, geolocation
3. **Pivot to the raw events**
```kql
   SecurityEvent
   | where IpAddress == "<attacker_ip>"
   | where TimeGenerated > ago(2h)
   | project TimeGenerated, EventID, Account, LogonType, Activity
   | order by TimeGenerated desc
```

## Triage Questions
- Is the source IP from an expected business country/ASN?
- Is the targeted account a real, active user, or a default name (administrator, admin, root)?
- Was there a successful logon (4624) from the same IP in the last 24 hours?
- Is this IP attacking other VMs in our environment?
- Does the IP appear in any threat intelligence feeds (AbuseIPDB, AlienVault OTX)?

## Containment Actions
1. **Block the source IP at the NSG or Azure Firewall**
   - Azure Portal → VM → Networking → Add inbound deny rule for source IP
   - Priority: lower number than the RDP allow rule
2. **If a successful logon occurred:**
   - Immediately disable the compromised account
   - Force password reset for the user
   - Capture VM memory and disk snapshot for forensics before remediation
3. **Notify the SOC lead** if 5+ accounts targeted or successful logon detected

## Eradication
1. Review all activity from the source IP in the last 7 days
2. Hunt for lateral movement: scheduled tasks, services, new local accounts
3. Validate no persistence mechanisms were installed
4. Check Defender for Cloud for related alerts

## Recovery
1. Re-enable accounts with new credentials and enforce MFA
2. Document indicators of compromise (IPs, accounts, timestamps)
3. Update the analytics rule threshold if false positives observed
4. Add the source IP to the Sentinel threat intelligence watchlist

## Lessons Learned (template — fill in after each real incident)
- What worked well?
- What was slow or missing?
- Did the detection rule need tuning?
- Should we add automation (block IP via Logic App)?

## Mapping to ACSC Essential Eight
| Control | Relevance |
|---|---|
| Multi-factor authentication | Would defeat all password-based brute force |
| Restrict administrative privileges | Reduces the attack surface for "admin" accounts |
| Patch operating systems | Mitigates post-compromise exploitation |
| Application control | Prevents attacker tools from running post-compromise |