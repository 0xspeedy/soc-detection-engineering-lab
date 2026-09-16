# Incident Investigation Report

**Incident ID:** INC-2026-002
**Classification:** Credential Access — Brute Force / Multiple Failed Logon Attempts
**Environment:** HOMELAB.LOCAL (isolated Active Directory + Splunk SOC lab)
**Reported by:** Ahmed Mahdy, IT Support Engineer (Lab Simulation)
**Date of Report:** September 15, 2026
**Framework:** NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)

---

## 1. Preparation

Prior to this incident, the following detection capability was in place:

- Splunk Enterprise (SPLUNK01) receiving forwarded Windows Security and Sysmon logs from both domain machines (DC01, WKS01) via Splunk Universal Forwarder
- A saved detection search, **"Detect - Multiple Failed Logons (Possible Brute Force,"** flagging any account with 3 or more failed logon attempts (Event ID 4625) within the search window
- A corresponding scheduled alert, **"Alert - Multiple Failed Logons (Possible Brute Force,"** running hourly and logging to Splunk's Triggered Alerts
- A Sigma rule (`multiple_failed_logons.yml`) documenting this detection logic in a vendor-neutral format, mapped to MITRE ATT&CK technique T1110 (Brute Force)
- Domain-wide Account Lockout Policy (5 invalid attempts, 15-minute lockout duration) configured via Default Domain Policy

## 2. Detection & Analysis

**2.1 Initial Detection**

At approximately 19:03 EDT on September 15, 2026, the account `jsmith` (IT Department OU) generated 5 consecutive failed logon attempts from workstation `WKS01`, exceeding both the custom detection threshold (3+) and the domain's account lockout threshold (5).

**2.2 Splunk Query Used**

```spl
index=* sourcetype=WinEventLog:Security EventCode=4625
| stats count as failed_attempts, min(_time) as first_attempt, max(_time) as last_attempt by Account_Name, host
| where failed_attempts >= 3
| convert ctime(first_attempt) ctime(last_attempt)
| table Account_Name, host, failed_attempts, first_attempt, last_attempt
```

**Result:** `jsmith` on host `WKS01` (reported hostname: `DESKTOP-O3FRQTS`) — 5 failed attempts.

**2.3 Corroborating Evidence**

Following the failed logon pattern, Windows Security Event ID **4740** (account lockout) was logged on the Domain Controller (DC01 / `WIN-C8DJH7L7ST8`), confirming the account lockout policy engaged as configured:

```spl
index=* sourcetype=WinEventLog:Security EventCode=4740
| table _time, host, Account_Name
```

**2.4 Scope Assessment**

- **Affected account:** `jsmith` only — no other domain accounts showed a matching pattern in the same window
- **Source host:** `WKS01`, the account's normal assigned workstation — no indication of a foreign or unexpected source system
- **No successful authentication** occurred prior to lockout — the account was locked before any valid credential was accepted
- No corresponding suspicious Sysmon process-creation activity (e.g., credential-dumping tools, unusual remote-access binaries) was observed on `WKS01` in the same time window, reducing the likelihood of active malware-driven credential attack

**2.5 Determination**

Given the source host matches the user's normal workstation and no corroborating malicious process activity was found, this event was assessed as **consistent with a simulated/benign trigger** (in a production environment, this same evidence trail would normally be assessed against the user's own account of events — e.g., confirming with the employee whether they mistyped their password — before ruling out malicious intent).

## 3. Containment, Eradication & Recovery

- **Containment:** Not required beyond the automatic account lockout already enforced by domain policy — the lockout itself served as the containment control, preventing further authentication attempts against the account.
- **Eradication:** No malicious artifact, persistence mechanism, or unauthorized access was identified; no eradication action was necessary.
- **Recovery:**
  1. Confirmed lockout status: `Get-ADUser jsmith -Properties LockedOut` → `True`
  2. Unlocked the account via Active Directory Users and Computers (Account tab → Unlock account)
  3. Verified recovery: `Get-ADUser jsmith -Properties LockedOut` → `False`
  4. Confirmed `jsmith` could authenticate successfully post-unlock

## 4. Post-Incident Activity

**Lessons learned / process notes:**
- The custom detection (3+ failed attempts) triggered ahead of the domain lockout threshold (5), which in a production environment would give a SOC analyst a window to intervene — e.g., proactively contacting the user — before the account actually locks and impacts their ability to work.
- Detection coverage for this scenario now exists at three levels: a saved Splunk search, a scheduled alert, and a documented Sigma rule — giving the detection portability beyond this specific Splunk instance.
- **Recommendation:** tune the custom detection's alert schedule from hourly to a shorter interval (e.g., every 5-15 minutes) in a production deployment, since brute-force attempts are often time-sensitive and an hourly check may detect the pattern well after the account has already locked.
- **Recommendation:** correlate this detection with source-IP or source-host reputation data where available, to help distinguish a user's own mistyped password from an external or unauthorized system attempting authentication.
- **Recommendation:** consider enabling MFA for accounts in privileged groups (e.g., IT-Admins) to reduce reliance on password-only authentication as the sole control against credential-guessing attempts.

---

*This report was produced as part of a self-directed home lab exercise simulating SOC detection engineering and incident response workflows, structured against NIST SP 800-61 Rev. 2. All systems, accounts, and data referenced are contained within an isolated, non-production lab environment (HOMELAB.LOCAL).*
