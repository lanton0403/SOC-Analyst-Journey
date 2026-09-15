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