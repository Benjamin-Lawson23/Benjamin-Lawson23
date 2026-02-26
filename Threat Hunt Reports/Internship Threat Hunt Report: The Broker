# Threat Hunt Report  
## Suspected Intrusion Investigation  

**Client:** Ashford Sterling Recruitment  
**Assessment Type:** Post-Compromise Threat Hunt  
**Severity:** Critical  
**Status:** Confirmed Multi-Stage Intrusion  

---

# 1. Executive Summary

This investigation confirmed that an attacker gained access through a malicious file disguised as a CV, established command and control (C2) communications, harvested credentials, moved laterally across systems, accessed financial data, staged it for exfiltration, and deployed multiple persistence mechanisms to maintain access.

The attacker demonstrated structured, hands-on-keyboard activity consistent with a human-operated intrusion rather than automated malware.

---

# 2. Environment Scope

## Compromised Hosts

- `as-pc1` (Initial Access)
- `as-pc2` (Lateral Movement)
- `as-srv` (Server Target)

## Compromised / Malicious Accounts

- `sophie.turner`
- `david.mitchell`
- `svc_backup` (attacker-created)

---

# 3. Investigation Findings (With Context & KQL Evidence)

---

# INITIAL ACCESS

## 3.1 Initial Vector

**Malicious Filename:**  
`daniel_richardson_cv.pdf.exe`

**What Happened:**  
A file disguised as a PDF CV was actually an executable. The double file extension likely tricked the user into thinking it was a document rather than a program.

**Execution Method:**  
Launched by `explorer.exe`, meaning it was manually double-clicked.

### KQL Used

```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ActionType,
          DeviceName, FileName, InitiatingProcessFileName
```

---

## 3.2 Payload Hash

**SHA256:**  
`48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

**What Happened:**  
The file’s cryptographic hash uniquely identifies the malware. This same hash later reappears under a renamed binary, confirming the attacker reused the original payload for persistence.

### KQL Used

```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName contains "daniel"
| project TimeGenerated, FileName,
          InitiatingProcessSHA256, SHA256
```

---

## 3.3 Suspicious Child Process

**Spawned Process:**  
`notepad.exe`

**Command Line:**  
`notepad.exe ""`

**What Happened:**  
The malware spawned a legitimate Windows process (Notepad). This is often done to inject malicious code into a trusted process to avoid detection.

### KQL Used

```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName contains "daniel"
| project TimeGenerated, FileName,
          ProcessCommandLine
```

---

# COMMAND & CONTROL

## 4.1 C2 Domain

**Domain:**  
`cdn.cloud-endpoint.net`

**What Happened:**  
After execution, the malware established outbound communication to an attacker-controlled domain. This allowed the attacker to send commands and receive results.

### KQL Used

```kql
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName contains "daniel"
| project TimeGenerated, RemoteUrl,
          InitiatingProcessFileName
```

---

## 4.2 Staging Domain

**Domain:**  
`sync.cloud-endpoint.net`

**What Happened:**  
A secondary domain was used to host additional payloads and tools, indicating infrastructure prepared for extended operations.

### KQL Used

```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| project TimeGenerated, RemoteUrl,
          InitiatingProcessFileName
```

---

# CREDENTIAL ACCESS

## 5.1 Registry Hive Dumping

**Hives Targeted:**  
`SYSTEM`, `SAM`

**What Happened:**  
The attacker used `reg.exe save` to export the SYSTEM and SAM registry hives. These contain password hashes and system key material required for offline password cracking.

### KQL Used

```kql
DeviceProcessEvents
| where FileName =~ "reg.exe"
| where ProcessCommandLine has "save"
| where ProcessCommandLine has_any
    ("HKLM\\SAM","HKLM\\SYSTEM")
```

---

## 5.2 Credential Staging Location

**Directory:**  
`C:\Users\Public\`

**What Happened:**  
The exported credential files were saved to a publicly writable directory commonly abused by attackers.

### KQL Used

```kql
DeviceFileEvents
| where DeviceName == "as-pc1"
| where FolderPath startswith @"C:\Users\Public\"
```

---

## 5.3 Execution Identity

**User:**  
`sophie.turner`

**What Happened:**  
The credential dumping was performed under this user context, meaning the attacker was operating interactively using her account.

---

# DISCOVERY

## 6.1 Identity Confirmation

**Command:**  
`whoami`

**What Happened:**  
The attacker verified which user account they were operating as.

---

## 6.2 Share Enumeration

**Command:**  
`net.exe view`

**What Happened:**  
This command lists accessible network shares, helping the attacker identify file servers and data locations.

---

## 6.3 Local Admin Enumeration

**Group Queried:**  
`Administrators`

**What Happened:**  
The attacker checked which accounts had local administrator privileges to plan lateral movement.

---

# PERSISTENCE

## 7.1 Remote Tool Deployment

**Software:**  
`AnyDesk.exe`

**What Happened:**  
A legitimate remote administration tool was installed to provide persistent remote access that blends in with legitimate IT software.

---

## 7.2 Download Method

**Binary Used:**  
`certutil.exe`

**What Happened:**  
A native Windows tool was abused to download the remote access software, avoiding the need for custom downloaders.

---

## 7.3 Scheduled Task

**Task:**  
`MicrosoftEdgeUpdateCheck`

**What Happened:**  
A scheduled task was created to execute malware automatically, ensuring it would persist after reboot.

---

## 7.4 Renamed Payload

**Filename:**  
`RuntimeBroker.exe`

**What Happened:**  
The malware was renamed to resemble a legitimate Windows process, reducing suspicion.

---

## 7.5 Backdoor Account

**Account Created:**  
`svc_backup`

**What Happened:**  
A new local account was created to guarantee future access even if other accounts were reset.

---

# LATERAL MOVEMENT

## 8.1 Failed Tools

**Attempted:**  
`WMIC.exe`, `PsExec.exe`

**What Happened:**  
The attacker initially attempted common administrative remote execution tools, which failed.

---

## 8.2 Successful Pivot

**Binary Used:**  
`mstsc.exe`

**What Happened:**  
The attacker switched to Remote Desktop Protocol (RDP), successfully logging into another workstation.

---

## 8.3 Movement Path

**Path:**  
`as-pc1 > as-pc2 > as-srv`

**What Happened:**  
The attacker progressively moved from a workstation to another workstation and then to a server, increasing impact potential.

---

## 8.4 Compromised Account Used

**Account:**  
`david.mitchell`

**What Happened:**  
Valid credentials were used to authenticate during lateral movement, making activity appear legitimate.

---

# DATA ACCESS & STAGING

## 9.1 Sensitive File Accessed

`BACS_Payments_Dec2025.ods`

**What Happened:**  
A payroll/financial spreadsheet was accessed on the file server.

---

## 9.2 Editing Artifact

`.~lock.BACS_Payments_Dec2025.ods#`

**What Happened:**  
The presence of this lock file confirms the document was opened for editing, not just previewed.

---

## 9.3 Archive Creation

**Archive:**  
`Shares.7z`

**SHA256:**  
`6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

**What Happened:**  
Data was compressed into an archive, a common step before exfiltration to reduce size and simplify transfer.

---

# DEFENSE EVASION

## 10.1 Log Clearing

**Logs Cleared:**  
`System`, `Security`

**What Happened:**  
Event logs were deliberately cleared to remove evidence of malicious activity.

---

## 10.2 Reflective Code Loading

**ActionType:**  
`ClrUnbackedModuleLoaded`

**What Happened:**  
A .NET assembly was loaded directly into memory without being written to disk, bypassing traditional file-based detection.

---

## 10.3 Credential Theft Tool

**Tool:**  
`SharpChrome`  
**Host Process:** `notepad.exe`

**What Happened:**  
A credential harvesting tool was injected into Notepad to steal browser-stored credentials while remaining hidden inside a legitimate process.

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | User Execution | T1204 |
| Execution | Malicious File | T1204.002 |
| Credential Access | OS Credential Dumping | T1003.002 |
| Credential Access | Browser Credential Theft | T1555 |
| Persistence | Scheduled Task | T1053.005 |
| Persistence | Create Account | T1136 |
| Lateral Movement | RDP | T1021.001 |
| Discovery | Account Discovery | T1033 |
| Defense Evasion | Clear Windows Logs | T1070.001 |
| Defense Evasion | Reflective Code Loading | T1620 |
| Collection | Archive Collected Data | T1560 |

---

# Final Assessment

This was a deliberate, structured intrusion involving:

- Social engineering
- Credential theft
- Living-off-the-land techniques
- Remote administration abuse
- Financial data targeting
- Multi-layer persistence
- Log tampering

The attacker achieved multi-system control and accessed sensitive payroll data.

Immediate containment, credential resets, endpoint rebuilds, and domain-wide security review are required.
