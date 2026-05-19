# Incident Response Playbook: Successful Logon from Unusual Country

## Overview
- **Detection Rule:** Honeypot - Successful Logon from Unusual Country
- **MITRE ATT&CK:** T1078 (Valid Accounts), T1021.001 (Remote Services: RDP)
- **Severity:** High
- **Trigger Logic:** Successful logon (Event ID 4624, LogonType 10) from a source IP geolocated outside the expected country (Australia)
- **Response Window:** < 30 minutes

> **Geographic anomalies are high-fidelity indicators of credential theft or account takeover.** Treat as suspected compromise until proven otherwise.

## Triggering Conditions
- Successful RDP logon (LogonType 10) where the source IP's GeoIP country is not in the allowlist
- Allowlist for this lab: `Australia`
- In production, allowlist should include all countries where the user base legitimately operates

## Detection Phase

### 1. Confirm the incident
- Open the incident in Sentinel
- Note: incident number, account, source IP, GeoIP country/city, timestamp

### 2. Identify the user and their normal pattern

```kql
SecurityEvent
| where Account == "<compromised_account>"
| where EventID == 4624
| where TimeGenerated > ago(30d)
| where IpAddress != "-" and isnotempty(IpAddress)
| extend Country = tostring(geo_info_from_ip_address(IpAddress).country)
| summarize Logons = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by Country
| order by Logons desc
```

This shows the user's historical logon countries. The anomalous country should NOT appear in their history (or appear very rarely).

### 3. Check for "impossible travel"

If the user logged in from Australia recently AND from the anomalous country shortly after:

```kql
SecurityEvent
| where Account == "<compromised_account>"
| where EventID == 4624
| where TimeGenerated > ago(24h)
| where IpAddress != "-" and isnotempty(IpAddress)
| extend Country = tostring(geo_info_from_ip_address(IpAddress).country)
| project TimeGenerated, IpAddress, Country, LogonType
| order by TimeGenerated asc
```

If two logons from different countries occurred within a physically impossible travel time (e.g., Sydney at 09:00, Moscow at 10:30), this is a strong compromise indicator.

## Triage Questions

Before initiating containment, answer these:

1. **Is this a known travelling user?**
   - Check HR records / travel approvals
   - Check the user's calendar for international meetings
   - Contact the user via a verified out-of-band channel (mobile phone, NOT email — email may be compromised)

2. **Is this country in the user's recent history?**
   - First-time appearance = stronger compromise signal
   - Country they visit annually = lower signal

3. **Are there other anomalous indicators?**
   - Logon outside business hours?
   - New device/user-agent?
   - Geographic anomaly + privileged account = treat as critical
   - Did the foreign logon follow a brute-force pattern? (Check Rule 2 status)

4. **Is the source IP a known VPN/proxy/Tor exit?**
   - Check threat intelligence (AbuseIPDB, AlienVault OTX, ipinfo.io)
   - Corporate VPNs often appear as foreign IPs — verify legitimacy

5. **Is Conditional Access in place?**
   - For Entra ID: check the sign-in logs for risk flags
   - If risk was detected but logon succeeded, MFA may have been bypassed or fatigued

## Containment Actions

### If unauthorized access is confirmed (or strongly suspected)

1. **Revoke all active sessions for the account**
   - Entra ID: Users → select user → **Revoke sessions**
   - This forces re-authentication everywhere
   
2. **Disable the account temporarily**
   - Entra ID: Users → select user → toggle **Block sign-in**
   - Local accounts: disable via PowerShell or `lusrmgr.msc` on the affected host
   
3. **Block the source IP at the NSG**
   - Add deny rule at the perimeter
   - Submit IP to org-wide threat intelligence list

4. **Preserve session evidence**
   - Capture screenshots of the incident in Sentinel
   - Export the user's sign-in logs from Entra ID
   - Export SecurityEvent data for the user from the past 7 days

### If the user is verified to be travelling legitimately

1. **Update the geo-allowlist** in the analytics rule to include the new country temporarily
2. **Document the exception** with a ticket reference and expiry date
3. **Enforce step-up MFA** for the session if possible
4. **Continue monitoring** for any anomalous activity from that session

## Investigation Phase

### Determine what the foreign session accessed

```kql
SecurityEvent
| where Account == "<account>"
| where IpAddress == "<foreign_ip>"
| where TimeGenerated > ago(48h)
| project TimeGenerated, EventID, Activity, Computer, LogonType
| order by TimeGenerated asc
```

Look for:
- File access patterns
- Privilege escalation events (4672, 4732)
- Process executions (4688)
- New scheduled tasks or services

### Cross-reference with Entra ID sign-in logs

If the account is cloud-managed, check:
- Sign-in risk score
- Conditional Access policy hits
- MFA challenge results
- Device compliance status

### Check for related anomalies

```kql
SecurityEvent
| where IpAddress == "<foreign_ip>"
| where TimeGenerated > ago(7d)
| summarize Accounts = make_set(Account), Attempts = count() by EventID
```

If the same IP touched other accounts in your environment, expand the scope of the incident.

## Eradication

1. **Force password reset for the affected account**
2. **Force MFA re-registration** (revokes all trusted devices)
3. **Review all permissions** granted to the account — revoke unnecessary access
4. **Add the source IP to the threat intelligence watchlist**

## Recovery

1. **Re-enable the account** with new credentials and MFA
2. **Brief the user** on what happened and password hygiene
3. **Review the Conditional Access policy** — should this country trigger automatic MFA or block?
4. **Update the geo-anomaly detection rule** if the false-positive rate is too high

## Lessons Learned

Document after each true-positive incident:

- **Was MFA enforced?** If yes, how was it bypassed? (Fatigue, SIM swap, token theft, phishing?)
- **Was Conditional Access in place?** Did it flag the risk?
- **Was the account using a strong, unique password?**
- **How was the credential compromised?** (Phishing, leaked dump, malware?)
- **What's the time-to-detect for this rule?** Can it be improved?

## Mapping to ACSC Essential Eight

| Control | Relevance |
|---|---|
| Multi-factor authentication | Critical — first line of defence against credential theft |
| Restrict administrative privileges | If foreign logon was to a privileged account, blast radius is much larger |
| User application hardening | Browser-based credential theft is the most common vector |
| Patch applications | Reduces malware-based credential theft |
| Regular backups | Recovery readiness if data was exfiltrated |

## False Positive Considerations

This rule has higher false-positive potential than brute-force rules. Common legitimate triggers:

1. **Employee travel** — Most common false positive. Solution: integrate with HR travel system or maintain a known-traveller watchlist.
2. **VPN endpoints** — Corporate VPN egress points may appear as foreign IPs. Solution: maintain a list of known corporate VPN IPs.
3. **Cloud provider IPs** — Some legitimate services route through cloud egress in other countries. Solution: allowlist cloud provider ASNs (Azure, AWS, GCP).
4. **Mobile carriers** — Mobile data often appears with carrier-assigned IPs that geolocate inconsistently. Solution: tune severity down if logon is from a mobile user-agent.

In production, this rule should be paired with **Conditional Access** in Entra ID for prevention, not just detection.