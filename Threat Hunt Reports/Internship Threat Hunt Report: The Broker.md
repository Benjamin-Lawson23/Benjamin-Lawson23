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

## Initial Access – How the Attacker Got In
The compromise began on workstation **as-pc1** when a fake CV file was run: ``daniel_richardson_cv.pdf.exe``. This file was disguised to look like a normal PDF but was actually a program.

KQL used to identify the first malicious file seen on the host:

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, InitiatingProcessFileName
```
<img width="1234" height="428" alt="TH Question 01" src="https://github.com/user-attachments/assets/da7729f1-1920-4a0c-ab86-54d34d491c9b" />

The malicious file’s unique fingerprint (SHA256 hash) was:

**Initial payload hash:** 

``48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5``

KQL used to retrieve the hash of the payload initiated by the fake CV:

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName contains "daniel"
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, SHA256
```
<img width="1204" height="431" alt="TH Question 02" src="https://github.com/user-attachments/assets/7a7b02c1-8f99-42f5-8665-57ba2a791525" />

The fake CV was launched from **explorer.exe**, which indicates a normal user double‑clicked the file in Windows Explorer (e.g., from the Desktop or Downloads).

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName contains "daniel"
| order by TimeGenerated asc
```
<img width="1189" height="431" alt="TH Question 03" src="https://github.com/user-attachments/assets/c56e9930-764b-462e-aa2c-053fd7c0eb88" />

Once running, the malware spawned a built‑in Windows program, **notepad.exe**, as a **child process**. Using a legitimate program as a decoy can help attackers blend in.

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName contains "daniel"
| order by TimeGenerated asc
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessSHA256, SHA256
```
<img width="1135" height="426" alt="TH Question 04" src="https://github.com/user-attachments/assets/8fb631b7-3b93-4706-848d-ce3ddf94e5fd" />

The suspicious ``notepad.exe`` instance ran with an unusual command line: ``notepad.exe ""`` (Notepad opened with an empty string). This suggests the process was likely used as a “host” or decoy, not for genuine text editing:

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName contains "daniel"
| order by TimeGenerated asc
```
<img width="1211" height="56" alt="TH Question 05" src="https://github.com/user-attachments/assets/6f7a0834-a2ed-4eca-86e7-4676108413bd" />

## Command & Control – How the Attacker Phoned Home
After gaining a foothold on **as-pc1**, the payload started talking to an attacker‑controlled server over the internet (command and control, or “C2”).

**C2 domain used:**

``cdn.cloud-endpoint.net``

KQL used to identify outbound connections related to the malicious CV process:

```
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessFileName contains "daniel"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by TimeGenerated desc
```

The process responsible for this network traffic was the same malicious file:

**C2 process:**

``daniel_richardson_cv.pdf.exe``

(Same query as above.)

The attacker also used separate infrastructure to host additional payloads, pivoting to another workstation **as-pc2** and identifying:

**Payload staging domain:**

``sync.cloud-endpoint.net``

KQL used on the second host:

```
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| order by TimeGenerated desc
```

## Credential Access – Stealing Passwords and System Secrets
The attacker attempted to steal sensitive system secrets from the local machine’s registry, which can be used to crack passwords offline.

They used the Windows tool reg.exe with the save command to dump credential‑related hives:

Registry hives targeted: system, sam

These two hives together allow an attacker to attempt extracting password hashes from the machine.

```
DeviceProcessEvents
| where FileName =~ "reg.exe"
| where ProcessCommandLine has "save"
| where ProcessCommandLine has_any ("HKLM\\SAM", "HKLM\\SECURITY", "HKLM\\SYSTEM")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

The stolen data was saved under a public directory on as-pc1 (local staging) before being sent out. The exact path was identified by focusing on new or modified files on the host:

```
DeviceFileEvents
| where DeviceName == "as-pc1"
| where ActionType in ("FileCreated", “FileCreatedOrModified")
```

When we looked at where those files were written in the Public user directory, we saw that the actions were executed under:

User performing the staging: sophie.turner

```
DeviceFileEvents
| where DeviceName == "as-pc1"
| where FolderPath startswith @"C:\Users\Public\"
| where ActionType in ("FileCreated", "FileModified")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName,
         InitiatingProcessFileName, FolderPath, FileName
| order by TimeGenerated desc
```

## Discovery – Understanding the Environment
Before moving further, the attacker gathered information about the environment.

They first confirmed which account they were running as, using the command:

User context command: whoami

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where InitiatingProcessCommandLine contains “whoami"
```

They then enumerated network resources (shared folders on the network) with:

Network enumeration command: net.exe view

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine contains "net"
| project TimeGenerated, AccountName, InitiatingProcessCommandLine, ProcessCommandLine
```

To understand which users had elevated rights, they queried local administrator group membership, targeting the Administrators group:

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("localgroup", "Administrators")
| project TimeGenerated, DeviceName, AccountName,
         InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated desc
```

## Persistence – Ensuring They Could Get Back In
The attacker deployed a legitimate remote‑access tool (remote desktop/control software) to maintain ongoing access:

Remote tool installed: AnyDesk.exe

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("anydesk", "teamviewer", "screenconnect", "connectwise", "splashtop", "logmein", "remote")
| project Timestamp, DeviceName, AccountName,
         FileName, ProcessCommandLine
| order by Timestamp desc
```

The hash of the AnyDesk binary was:

Remote tool hash: f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("anydesk", "teamviewer", "screenconnect", "connectwise", "splashtop", "logmein", "remote")
| project Timestamp, DeviceName, AccountName,
         FileName, ProcessCommandLine, InitiatingProcessSHA256, SHA256
| order by Timestamp desc
```

To download this tool, they abused a built‑in Windows utility often misused by attackers:

Download binary used: certutil.exe

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where FileName in~ ("certutil.exe","bitsadmin.exe","powershell.exe","curl.exe","mshta.exe")
| where ProcessCommandLine has_any ("http","https","ftp")
| project TimeGenerated, DeviceName, AccountName,
         FileName, ProcessCommandLine
| order by TimeGenerated desc
```

After installation, the attacker accessed the AnyDesk configuration file, likely to set up unattended access:

Configuration file path: C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf

```
DeviceProcessEvents
| where FileName in~ ("cmd.exe","powershell.exe")
| where ProcessCommandLine has @"AppData"
| where ProcessCommandLine has_any ("type ","Get-Content","gc ","more ")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
```

Within this configuration activity, we see a password being set for unattended access:

Configured unattended access password: intrud3r

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where ProcessCommandLine has_any ("password","pwd","pass","--pass","-p ")
| project TimeGenerated, AccountDomain, AccountName, InitiatingProcessCommandLine
```
AnyDesk was deployed broadly, giving the attacker remote access across multiple machines:

Hosts with AnyDesk installed: as-pc1, as-pc2, as-srv

```
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName has_any ("AnyDesk")
| project TimeGenerated, DeviceName, FileName, FolderPath
| distinct DeviceName
| order by DeviceName asc
```

The attacker also created a dedicated backdoor local account for future logins:

New local account created: svc_backup

```
DeviceProcessEvents
| where FileName == "net.exe"
| where ProcessCommandLine has_all ("user", "/add")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
```

To allow a previously disabled account to be used, they re‑enabled it using:

Account activation parameter: /active:yes

```
DeviceProcessEvents
| where FileName == "net.exe"
| where ProcessCommandLine contains "/active:yes"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

This action was performed by:

User performing activation: david.mitchell

(Same KQL as above, inspecting AccountName.)

They created a scheduled task to keep a malicious program running regularly:

Scheduled task name: MicrosoftEdgeUpdateCheck

```
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated desc
```

The actual payload for this task was a renamed executable meant to look legitimate:

Renamed persistence payload: RuntimeBroker.exe

```
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated desc
```

That RuntimeBroker.exe shared the same hash as the original malicious CV:

Persistence payload hash: 48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5

```
DeviceFileEvents
| where FileName == "RuntimeBroker.exe"
| project TimeGenerated, DeviceName, FileName, SHA256
```

## Lateral Movement – Spreading to Other Systems
The attacker tried several remote execution tools from as-pc1, but some attempts failed:

Failed execution tools tried: WMIC.exe, PsExec.exe

```
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where FileName has_any ("psexec.exe","wmic.exe","schtasks.exe","sc.exe","powershell.exe","winrm.cmd")
| project TimeGenerated, DeviceName, AccountName,
         FileName, ProcessCommandLine
| order by TimeGenerated desc
```

Those failed attempts targeted:

Remote target in failed attempts: as-pc2
(Identified from ProcessCommandLine using the same query as above.)

Eventually, the attacker succeeded in moving laterally using Remote Desktop:

Executable used for successful pivot: mstsc.exe (the standard Windows Remote Desktop client)

```
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where RemotePort == "3389"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName
```

By examining successful network connections across hosts, we see the full movement path:

Lateral movement path: as-pc1 > as-pc2 > as-srv

```
DeviceNetworkEvents
| where DeviceName has_any ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, InitiatingProcessFileName
```

A valid user account was used for successful logons during this movement:

Compromised account used for lateral movement: david.mitchell

```
DeviceLogonEvents
| where DeviceName in ("as-pc1", "as-pc2")
| project TimeGenerated, DeviceName, AccountName, ActionType
| order by TimeGenerated asc
```


## Data Access & Exfiltration Preparation – What They Touched
On the file server, the attacker accessed a sensitive finance‑related document:

Sensitive document accessed: BACS_Payments_Dec2025.ods

```
DeviceFileEvents
| where FileName has_any (".xlsx",".xls",".csv",".ods",".pdf")
| where FileName has_any ("pay","payment","payroll","finance","invoice","bank","bacs")
| project TimeGenerated, DeviceName, FileName, FolderPath
| order by TimeGenerated desc
```

An OpenDocument lock file showed that the document was opened in edit mode (not just read‑only):

Evidence of modification/open for editing: .~lock.BACS_Payments_Dec2025.ods#

```
DeviceFileEvents
| where FileName has_any (".xlsx",".xls",".csv",".ods",".pdf")
| where FileName has_any ("pay","payment","payroll","finance","invoice","bank","bacs")
| project TimeGenerated, ActionType, DeviceName, FileName
```

The document was accessed from:

Workstation that accessed the document: as-pc2
(Identified from DeviceName using the same KQL as above.)

Before exfiltration, the attacker bundled data into an archive:

Archive filename: Shares.7z

```
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FileName endswith ".zip"
    or FileName endswith ".rar"
    or FileName endswith ".7z"
    or FileName endswith ".cab"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

The archive’s hash was:

Archive hash: 6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048

```
DeviceFileEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "FileCreated"
| where FileName endswith ".zip"
    or FileName endswith ".rar"
    or FileName endswith ".7z"
    or FileName endswith ".cab"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessSHA256
| order by TimeGenerated desc
```

## Defense Evasion & In‑Memory Activity – Hiding Their Tracks
To cover their tracks, the attacker cleared important Windows event logs:

Logs cleared (examples): System, Security

```
DeviceProcessEvents
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has " cl "
| project TimeGenerated,
          DeviceName,
          InitiatingProcessAccountName,
          ProcessCommandLine
| order by TimeGenerated desc
```

Telemetry also showed reflective loading, where code is loaded directly into memory rather than from disk, making it harder to detect:

ActionType indicating reflective loading: ClrUnbackedModuleLoaded

```
DeviceEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| distinct ActionType
```

Within those events, we identified a credential theft tool:

In‑memory credential theft tool: SharpChrome
(This is commonly used to steal saved passwords and cookies from the Chrome browser.)

```
DeviceEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| project TimeGenerated, ActionType, AdditionalFields
```

The malicious assembly was hosted inside a legitimate Windows process:

Host process for in‑memory tool: notepad.exe

```
DeviceEvents
| where DeviceName in ("as-pc1", "as-pc2", "as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| project TimeGenerated,
          DeviceName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by TimeGenerated desc
```
---

# 4. High-Level Summary

A user on as-pc1 opened a fake CV file (daniel_richardson_cv.pdf.exe), which was actually malware.

That malware contacted remote domains (cdn.cloud-endpoint.net and sync.cloud-endpoint.net) controlled by the attacker and used Notepad in the background as a decoy.

The attacker stole system secrets by dumping critical registry hives (system, sam) and staging those files locally under a user tied to sophie.turner.

They then explored the network, checked their own identity (whoami), listed network shares (net.exe view), and looked at who had local admin rights (Administrators group).

For persistence, they installed AnyDesk on several systems (as-pc1, as-pc2, as-srv), configured a password (intrud3r), re‑enabled a disabled account with /active:yes, created a new backdoor account svc_backup, and added a scheduled task (MicrosoftEdgeUpdateCheck) that ran a disguised copy of the original malware (RuntimeBroker.exe).

They attempted various remote execution tools (WMIC.exe, PsExec.exe) against as-pc2, then successfully pivoted using Remote Desktop (mstsc.exe), ultimately moving along the path as-pc1 > as-pc2 > as-srv using the account david.mitchell.

On the server, they accessed and edited a sensitive finance document (BACS_Payments_Dec2025.ods), then bundled data into an archive (Shares.7z) in preparation for exfiltration.

Finally, they cleared key event logs (System, Security) and used an in‑memory tool (SharpChrome) injected into notepad.exe to steal browser‑stored credentials, making detection and forensics more difficult.

This sequence confirms a full intrusion lifecycle on Ashford Sterling Recruitment’s environment: initial access, C2, credential theft, discovery, lateral movement, persistence, data access, and evidence tampering.

---

# 5. MITRE ATT&CK Mapping

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

# 6. Overall Assessment

This was a deliberate, structured intrusion involving:

- Social engineering
- Credential theft
- Living-off-the-land techniques
- Remote administration abuse
- Financial data targeting
- Multi-layer persistence
- Log tampering

The attacker achieved multi-system control and accessed sensitive payroll data.

---

# 7. Remediation Recommendations

## Immediate Actions

- Reset all credentials (domain + local)

- Remove AnyDesk from all hosts

- Delete svc_backup account

- Remove scheduled task

- Rebuild compromised endpoints

- Block cloud-endpoint.net domains

## Medium-Term

- Implement application allowlisting

- Enforce MFA on all privileged accounts

- Disable legacy admin protocols (WMIC, SMB where possible)

- Deploy EDR tamper protection

## Long-Term

- User phishing awareness training

- Strict file extension visibility policies

- Regular credential hygiene audits

- Continuous threat hunting program
