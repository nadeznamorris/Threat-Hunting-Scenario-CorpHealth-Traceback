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
