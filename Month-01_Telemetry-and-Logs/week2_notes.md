# Week 02: Windows Event Logs & Endpoint Triage

An operational guide covering fundamental Windows Security Event IDs, authentication mechanics, and practical triage queries for SOC analysts.

---

## 1. Core Security Event IDs

| Event ID | Name | Critical Fields | Threat Context |
| :--- | :--- | :--- | :--- |
| **4624** | An account was successfully logged on | `TargetUserName`, `LogonType`, `IpAddress`, `ElevatedToken` | Validates initial access, lateral movement, or unauthorized remote sessions. |
| **4625** | An account failed to log on | `TargetUserName`, `Status`, `Substatus`, `IpAddress` | High volume indicates credential brute-forcing or password spraying. |
| **4672** | Special privileges assigned to new logon | `SubjectUserName`, `PrivilegeList` (`SeDebugPrivilege`, `SeBackupPrivilege`) | Signals privilege escalation or initialization of high-integrity administrative sessions. |
| **4720** | A user account was created | `SubjectUserName` (actor), `TargetUserName` (created user) | Common persistence mechanism via rogue local administrator or backdoor accounts. |

---

## 2. Key Logon Types (Event ID 4624)

* **Type 2 (Interactive):** Physical keyboard/console login or direct workstation unlock.
* **Type 3 (Network):** Remote network authentication without an interactive shell (e.g., SMB shares on `TCP/445`, Kerberos/NTLM authentication).
* **Type 5 (Service):** Background service initialization managed by the Service Control Manager (frequently runs under `SYSTEM` or dedicated service accounts).
* **Type 10 (RemoteInteractive):** Remote Desktop Protocol (RDP) sessions (`TCP/3389`). Unscheduled Type 10 sessions from external or unapproved subnets warrant immediate investigation.

---

## 3. Attack Lifecycle Correlation

```text
[Recon / Credential Abuse]  --> Event ID 4625 (Surge of authentication failures)
            │
            ▼
[Initial Foothold]          --> Event ID 4624 (Logon Type 10 via RDP or Type 3 via SMB)
            │
            ▼
[Privilege Escalation]      --> Event ID 4672 (SeDebugPrivilege / SYSTEM context granted)
            │
            ▼
[Persistence Mechanism]     --> Event ID 4720 (Creation of unauthorized shadow accounts)

```

---

## 4. Triage & Filtering Syntax

### Event Viewer XML Query (Filter 4624 for RDP Only)

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624)]] 
      and 
      *[EventData[Data[@Name='LogonType']='10']]
    </Select>
  </Query>
</QueryList>

```

### PowerShell Quick Triage Command

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 50 |
Where-Object { $_.Properties[8].Value -in 2, 10 } |
Select-Object TimeCreated,
              @{N='User'; E={$_.Properties[5].Value}},
              @{N='LogonType'; E={$_.Properties[8].Value}},
              @{N='IP'; E={$_.Properties[18].Value}}

```

---

## 5. Sysmon Telemetry & Advanced Endpoint Visibility

Sysmon bridges the visibility gap of standard Windows logs by capturing command-line parameters, parent-child process lineages, and process-level network sockets.

### Key Sysmon Event IDs

| Event ID | Event Name | Critical Fields | Threat Context |
| :--- | :--- | :--- | :--- |
| **1** | Process Creation | `CommandLine`, `ParentImage`, `ParentCommandLine`, `Hashes` | Reveals obfuscated CLI parameters (`-W Hidden`, `-enc`), LOLBins abuse, and suspicious parentage. |
| **3** | Network Connection | `Image`, `DestinationIp`, `DestinationPort`, `Initiated` | Links local binaries directly to outbound network traffic (C2 beaconing, payload download). |
| **11** | FileCreate | `Image`, `TargetFilename` | Detects dropped staging binaries in staging paths (`Temp`, `AppData`, `ProgramData`). |
| **13** | RegistryEvent (Value Set) | `Image`, `TargetObject`, `Details` | Identifies persistence mechanisms targeting autostart keys (`Run`, `RunOnce`). |

---

## 6. Anti-Forensics: Log Tampering Detection

Adversaries routinely clear security logs to blind responders during post-exploitation.

| Event ID | Log Provider | Event Definition | Threat Significance |
| :--- | :--- | :--- | :--- |
| **1102** | Security | The audit log was cleared | High-severity alert; logs the user identity executing log wiping (`wevtutil cl Security`). |
| **104** | System | The log file was cleared | Triggers when administrative users clear application, system, or custom service logs. |

---

## 7. Windows Security vs. Sysmon: Operational Boundary

* **Windows Security Logs (Identity & Access):** Answers *WHO* logged on, *WHERE* they authenticated from, and *WHAT* privileges were granted (`4624`, `4625`, `4672`, `4720`).
* **Sysmon Telemetry (Process & Behavior):** Answers *HOW* binaries executed, *WHAT* commands were typed, and *WHICH* network sockets/files were altered (`1`, `3`, `11`, `13`).

---

## 8. Threat Hunting: Common Attack Techniques & Artifacts

Threat hunting shifts from reactive alerting to proactive artifact discovery across identity, execution, and persistence vectors.

### Core Attack Techniques & Detection Logic

| Technique | MITRE ATT&CK | Core Detection Telemetry | Key Indicators & Detection Logic |
| :--- | :--- | :--- | :--- |
| **LSASS Memory Dumping** | T1003.001 | Sysmon ID 10 (`ProcessAccess`), ID 11 (`FileCreate`) | Untrusted process targeting `lsass.exe` requesting suspicious memory access rights (`GrantedAccess` masks like `0x1010` or `0x1FFFFF`). |
| **PowerShell Obfuscation** | T1059.001 | Sysmon ID 1, Win Event 4104 (ScriptBlock) | CLI parameters attempting evasion (`-enc`, `-w hidden`, `-ep bypass`) paired with un-obfuscated script code captured in Event 4104. |
| **Registry Run Persistence** | T1547.001 | Sysmon ID 13 (`RegistryEvent`) | Modification of autostart keys (`...\CurrentVersion\Run` or `RunOnce`) pointing to dropped payloads in staging folders (`Temp`, `AppData`). |