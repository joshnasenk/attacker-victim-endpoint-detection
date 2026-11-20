# Attacker–Victim Simulation and Endpoint Threat Detection Using Sysmon and Splunk

> A controlled Kali Linux → Windows 11 lab that generates endpoint and network telemetry with Sysmon and uses Splunk Enterprise to reconstruct the activity through process, network and file-event correlation.

**Author:** Joshna · B.Tech ECE, PES University, Bengaluru
**Lab date:** 20 November 2026 (all timestamps IST, UTC+05:30, as displayed in Splunk)
**Status:** Lab complete · Report v1.0

> **Scope statement.** This project uses a **benign, controlled** simulation. It did **not** deploy malware or Meterpreter, did **not** establish a reverse shell, did **not** disable Windows Defender and did **not** demonstrate post-exploitation. It is an attacker–victim *simulation* focused on telemetry collection, investigation and detection engineering.

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Introduction](#2-introduction)
3. [Project Objectives](#3-project-objectives)
4. [System Requirements and Lab Architecture](#4-system-requirements-and-lab-architecture)
5. [Methodology and Implementation](#5-methodology-and-implementation)
6. [Sysmon Configuration and Data Collection](#6-sysmon-configuration-and-data-collection)
7. [Splunk Log Ingestion and Event Investigation](#7-splunk-log-ingestion-and-event-investigation)
8. [Detection Engineering and SPL Queries](#8-detection-engineering-and-spl-queries)
9. [Results and Discussion](#9-results-and-discussion)
10. [Limitations](#10-limitations)
11. [Conclusion and Future Scope](#11-conclusion-and-future-scope)
12. [References](#12-references)

**Convention used in this report:** findings are labelled **[Observed]** (visible in captured evidence), **[Interpretation]** (analyst reasoning) or **[Assumption / To verify]** (not directly evidenced). Items marked `TODO` need evidence the author still has to supply.

---

## 1. Abstract

This project builds a two-VM attacker–victim lab in VMware Fusion (Kali Linux and Windows 11 ARM64) to study how endpoint telemetry can be used to reconstruct attack-like activity. From Kali, Nmap was used to enumerate the Windows host; a benign test payload and a benign PowerShell script were then served over HTTP from Kali and pulled onto the Windows endpoint, where the script was executed and wrote a marker file. Microsoft Sysmon recorded process creation (Event ID 1), network connections (Event ID 3) and file creation (Event ID 11), and the events were ingested into Splunk Enterprise 10.4.2.

Using SPL, the activity was reconstructed as a single chain: **interactive PowerShell session → HTTP connections to the Kali host on port 8000 → file creation in an `AttackLab` folder → child PowerShell process executing the downloaded script → marker file creation**. Process GUIDs rather than PIDs were used for lineage correlation. Detection searches were written for PowerShell network activity and for Kali-to-Windows transfer plus script execution. A suspicious-argument search returned zero matches; analysis of that negative result exposed a regex coverage gap (Section 9.4), which is itself a useful detection-engineering finding.

## 2. Introduction

Attack stages such as reconnaissance, tool transfer and script execution each leave different traces: network flows, process trees and file-system changes. No single log source tells the whole story. The value of a SIEM investigation lies in **joining** these traces.

Sysmon extends Windows logging with fields the default Security log lacks — full command lines, parent process, process GUIDs, destination IPs and file targets. Splunk provides the search and correlation layer. This project uses a safe, repeatable scenario to exercise that pipeline end to end and to document the queries, evidence and limits.

## 3. Project Objectives

1. Build an attacker–victim lab using Kali Linux and Windows 11 in VMware Fusion.
2. Perform host and service discovery with Nmap.
3. Simulate a controlled file transfer from Kali to Windows over HTTP.
4. Simulate script execution with a benign PowerShell script that leaves an observable marker.
5. Collect endpoint telemetry with Sysmon (Event IDs 1, 3, 11).
6. Ingest Sysmon events into Splunk and investigate them.
7. Correlate processes using PID, parent PID, Process GUID and Parent Process GUID.
8. Develop and evaluate SPL detections for PowerShell network activity and suspicious arguments.
9. Present the results in a Splunk dashboard.

## 4. System Requirements and Lab Architecture

### 4.1 Components

| Component | Role | Details |
|---|---|---|
| Host | Hypervisor host | macOS, VMware Fusion |
| Attacker VM | Recon and file hosting | Kali Linux, `eth0` **172.16.217.129/24** |
| Victim VM | Target, telemetry source | Windows 11 ARM64, hostname `Windows11`, IP **172.16.217.130** |
| Endpoint telemetry | Event generation | Microsoft Sysmon (`TODO`: version) |
| SIEM | Ingestion, search, dashboards | Splunk Enterprise **10.4.2** |
| Tools | Recon / delivery | Nmap 7.99, Python `http.server` (port 8000), Windows PowerShell 5.1 (`v1.0` path) |

### 4.2 Workflow

![Project workflow](docs/images/project_workflow.png)

```
Kali Linux (recon + simulation)  <-- network activity -->  Windows 11 ARM64 (benign activity + Sysmon)
                                                                    |  event collection
                                                                    v
                                                          Splunk Enterprise (correlation, detection)
                                                                    |
                                                                    v
                              Attack timeline · process-tree analysis · network indicators · detection queries
```

![VMware lab architecture](docs/images/1__vmware-lab-architecture.png)
*Figure 1 – Windows 11 and Kali VMs running side by side in VMware Fusion.*

![Kali IP configuration](docs/images/2__kali-ip-configuration.png)
*Figure 2 – Kali `ip a`: `eth0` = 172.16.217.129/24.*

### 4.3 Network note

**[Observed]** Windows made outbound connections to public addresses (e.g. 104.20.23.154:443 and OneDrive traffic to 74.151.238.97), so the lab segment has **internet access** (consistent with a NAT-type VMware network).
**[Interpretation]** The lab is host-contained for attacker–victim traffic but should **not** be described as an air-gapped or fully isolated network. `TODO`: record the VMware network mode (NAT / host-only) used.

### 4.4 Safety and authorisation

All activity was performed against VMs owned by the author, on a private virtual subnet. The payload and script are benign: they only create text files and a marker file.

## 5. Methodology and Implementation

### 5.1 Environment setup
Kali Linux and Windows 11 were installed as separate VMs in VMware Fusion and placed on the same virtual subnet (172.16.217.0/24). Connectivity was confirmed with Nmap (Section 5.2).

### 5.2 Reconnaissance (Nmap)

```bash
nmap -sV -Pn 172.16.217.130
```

`-sV` fingerprints service versions; `-Pn` skips host discovery and treats the host as up (useful because Windows Firewall often drops ping).

![Nmap service discovery](docs/images/3__nmap-service-discovery.png)
*Figure 3 – Nmap output (completed in 34 s; 994 closed ports).*

**[Observed]** open ports on 172.16.217.130:

| Port | Service | Version/Info |
|---|---|---|
| 135/tcp | msrpc | Microsoft Windows RPC |
| 139/tcp | netbios-ssn | Microsoft Windows netbios-ssn |
| 445/tcp | microsoft-ds | SMB (version not resolved) |
| 5432/tcp | postgresql | PostgreSQL DB |
| 8000/tcp | http | Splunkd httpd |
| 8089/tcp | ssl/http | Splunkd httpd |

MAC `00:0C:29:67:F7:90` (VMware OUI), OS: Windows.

**[Interpretation]** The scan reveals that Splunk (8000 web, 8089 management) is running **on the victim host itself** — see Limitations. The PostgreSQL listener (5432) was not explained in the evidence (`TODO`: identify the owning application).

### 5.3 Controlled file transfer (Kali → Windows)

A benign test payload and script were hosted on Kali with Python's built-in web server (default port 8000):

```bash
# On Kali, in the directory holding lab_payload.txt and lab_simulation.ps1
python3 -m http.server 8000
```

Windows retrieved the files from `http://172.16.217.129:8000/` using PowerShell. `TODO`: paste the exact download commands used (e.g. `Invoke-WebRequest … -OutFile …`); they are not captured in the Sysmon evidence (see 10.3).

A browser tab titled *"Directory listing for /"* is visible in the Splunk screenshots, consistent with the Python server's index page.

An earlier dry run created a benign file locally on the victim to validate Sysmon file-creation logging:

```powershell
Set-Content -Path "$env:USERPROFILE\Desktop\LabTest\Incoming\invoice_update.txt" -Value "BENIGN SECURITY LAB TEST"
Test-Path  "$env:USERPROFILE\Desktop\LabTest\Incoming\invoice_update.txt"   # True
Get-Item   "$env:USERPROFILE\Desktop\LabTest\Incoming\invoice_update.txt"
```

![Benign file creation on Windows](docs/images/4__file-delivery-windows.png)
*Figure 4 – Benign test file (26 bytes) created in `LabTest\Incoming`. This is a **local** creation used to validate telemetry, not the HTTP transfer.*

### 5.4 Execution simulation

The downloaded `lab_simulation.ps1` was run from the existing PowerShell session:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\joshn\Desktop\AttackLab\lab_simulation.ps1
```

**[Observed]** the script created `remote_execution_marker.txt` in `AttackLab` about 2.6 s after the process started. `TODO`: include the script body.

### 5.5 Attack-simulation timeline (reconstructed from Splunk)

| Time (IST) | Sysmon EID | Process (PID) | Activity | Source |
|---|---|---|---|---|
| 09:52:33.447 | 1 | powershell.exe (1680), parent PID 4800 | Interactive PowerShell session starts | Fig. 7, 8 |
| 12:12:01.998 | 3 | powershell.exe (1680) | 172.16.217.130 → 104.20.23.154:443 | Fig. 6, 9 |
| 12:51:06.760 | 11 | powershell.exe (1680) | `AttackLab` folder created | Fig. 12 |
| 12:51:14.223 | 11 | powershell.exe (1680) | `lab_payload.txt` created | Fig. 12 |
| 12:51:15.932 | 3 | powershell.exe (1680) | Connection to **172.16.217.129:8000** (Kali) | Fig. 13 |
| 12:54:18.365 | 11 | powershell.exe (1680) | `lab_simulation.ps1` created | Fig. 12 |
| 12:54:19.469 | 3 | powershell.exe (1680) | Connection to **172.16.217.129:8000** (Kali) | Fig. 13 |
| 12:55:01.337 | 1 | powershell.exe (**13208**), parent 1680 | `-NoProfile -ExecutionPolicy Bypass -File …\lab_simulation.ps1` | Fig. 11, 13 |
| 12:55:03.981 | 11 | powershell.exe (13208) | `remote_execution_marker.txt` created | Fig. 12 |

**[Observed – to verify]** In both transfers the file-creation event is timestamped ~1–2 s *before* the matching network event. Plausible causes: Sysmon/ETW network-event latency, or the time field used by Splunk (`_time`) versus Sysmon's `UtcTime`. `TODO`: compare `UtcTime` in the raw XML before drawing conclusions from sub-second ordering.

## 6. Sysmon Configuration and Data Collection

Sysmon is a Windows system service and driver that writes detailed events to `Microsoft-Windows-Sysmon/Operational`. Three event types drive this project:

| Event ID | Name | Why it matters | Key fields used |
|---|---|---|---|
| **1** | Process creation | Shows what ran, with full command line and parent; basis of the process tree | `Image`, `ProcessId`, `ProcessGuid`, `ParentProcessId`, `ParentProcessGuid`, `CommandLine` |
| **3** | Network connection | Ties a network flow to the process that made it; reveals C2/download behaviour | `Image`, `ProcessId`, `SourceIp`, `DestinationIp`, `DestinationPort`, `Protocol` |
| **11** | File create | Shows what a process wrote to disk (dropped payloads, scripts, markers) | `TargetFilename`, `ProcessId`, `Image`, `User` |

Process GUIDs are unique per process instance, which makes them safer than PIDs for correlation because Windows **reuses PIDs**.

`TODO`: Sysmon version, configuration file (e.g. custom XML or a public baseline) and install command. Not provided in the evidence, so no configuration details are claimed here.

## 7. Splunk Log Ingestion and Event Investigation

Sysmon Operational events are ingested into `index=main` with sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. Events are searched as raw XML, so fields are extracted with `rex`. (`TODO`: document the input method, e.g. Splunk Universal Forwarder or local `inputs.conf` monitor stanza.)

### 7.1 Network investigation (Event ID 3)

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=3
| rex field=_raw "<Data Name='Image'>(?<Image>.*?)</Data>"
| rex field=_raw "<Data Name='SourceIp'>(?<SourceIP>.*?)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIP>.*?)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>.*?)</Data>"
| rex field=_raw "<Data Name='Protocol'>(?<Protocol>.*?)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessID>.*?)</Data>"
| table _time Image ProcessID SourceIP DestinationIP DestinationPort Protocol
| sort -_time
```

![Network connection analysis](docs/images/8__Sysmon_Network_Connection_Analysis.png)
*Figure 5 – 108 network-connection events in the baseline view.*

**[Observed]** 108 EID 3 events. Visible entries include OneDrive `FileCoAuth.exe` → 74.151.238.97, `powershell.exe` (1680) → 104.20.23.154, and `msedge.exe` sending IPv6 multicast (`ff02::fb`, mDNS-style).
**[Interpretation]** Most traffic is ordinary background noise, so filtering by process image (PowerShell) is a practical way to cut volume.

### 7.2 Narrowing to one process (PID 1680)

```spl
... | search EventCode=3 | ... | search ProcessID=1680
| table _time Image ProcessID SourceIP DestinationIP DestinationPort | sort -_time
```

![PowerShell network connection correlation](docs/images/9__PowerShell_Network_Connection_Correlation.png)
*Figure 6 – PID 1680 connected from 172.16.217.130 to 104.20.23.154:443 at 12:12:01.998.*

**[Observed]** One connection for PID 1680 at that point in time. **[Interpretation]** 104.20.23.154 is an external HTTPS endpoint; its ownership and purpose were not verified (`TODO`: WHOIS / reverse lookup; check what the session did at 12:12).

### 7.3 Process GUID correlation (Event ID 1)

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessID>.*?)</Data>"
| rex field=_raw "<Data Name='ProcessGuid'>(?<ProcessGuid>.*?)</Data>"
| rex field=_raw "<Data Name='ParentProcessGuid'>(?<ParentProcessGuid>.*?)</Data>"
| rex field=_raw "<Data Name='Image'>(?<Image>.*?)</Data>"
| search ProcessID=1680
| table _time Image ProcessID ProcessGuid ParentProcessGuid
```

![ProcessGuid correlation](docs/images/11__Sysmon_ProcessGuid_Correlation.png)
*Figure 7 – PID 1680 identified by `ProcessGuid {b46cdb52-cb09-6aff-888f-010000000800}`.*

**[Observed]** PID 1680 started 09:52:33.447 with the GUID above and `ParentProcessGuid {b46cdb52-8593-6a85-8100-000000000800}`.

### 7.4 Child-process investigation

```spl
... | search EventCode=1
| rex field=_raw "<Data Name='ParentProcessGuid'>(?<ParentProcessGuid>.*?)</Data>"
... 
| search ParentProcessGuid="{b46cdb52-cb09-6aff-888f-010000000800}"
| table _time Image ProcessID CommandLine
| sort _time
```

![Child process investigation](docs/images/12__Sysmon_Child_Process_Investigation.png)
*Figure 8 – Seven child processes of PID 1680 (first four visible).*

**[Observed]** children include `sc.exe queryex Splunkd` (PID 15644, 10:19:21.800), `NETSTAT.EXE -ano` (15068, 10:19:27.814), `findstr.exe :8000` (3564, 10:19:27.897) and a second `NETSTAT.EXE -ano` (4160).
**[Interpretation]** These match routine administrator checks (is the Splunk service running; is port 8000 listening) rather than attack behaviour — a useful baseline of what the same parent does legitimately.

### 7.5 Reconstructed process tree

```
PID 4800  (parent image not captured)
└─ powershell.exe  PID 1680   09:52:33  {b46cdb52-cb09-6aff-888f-010000000800}
   ├─ sc.exe        15644  10:19:21  queryex Splunkd
   ├─ NETSTAT.EXE   15068  10:19:27  -ano
   ├─ findstr.exe    3564  10:19:27  :8000
   ├─ NETSTAT.EXE    4160  ~10:25    -ano
   ├─ powershell.exe 7400  11:25:53  -File ...\LabTest\simulation.ps1
   ├─ powershell.exe 4328  11:26:26  -NoProfile -ExecutionPolicy Bypass -File ...\LabTest\simulation.ps1
   └─ powershell.exe 13208 12:55:01  -NoProfile -ExecutionPolicy Bypass -File ...\AttackLab\lab_simulation.ps1
```

**[Assumption / To verify]** The last three children are inferred from the script-execution searches (Section 7.6); the Fig. 8 capture only shows four of the seven rows.

### 7.6 Script-execution investigation

```spl
... | search EventCode=1 ... 
| where match(CommandLine,"(?i)simulation\.ps1")
| table _time Image ProcessID ParentProcessID CommandLine
| sort -_time
```

![Attack simulation process creation](docs/images/22__Attack_Simulation_Process_Creation.png)
*Figure 9 – Three `simulation.ps1` executions, all with parent PID 1680.*

Then a lineage check around the AttackLab run:

```spl
... | where ProcessID="13208" OR ParentProcessID="13208" OR ProcessID="1680"
| table _time Image ProcessID ParentProcessID CommandLine | sort _time
```

![Parent-child verification](docs/images/24__Attack_Simulation_Process_Parent_Child.png)
*Figure 10 – 13208 is a child of 1680; 1680's own parent is 4800.*

**[Observed]** No Event ID 1 record had `ParentProcessID=13208`, i.e. the script spawned no child processes in the captured data.

### 7.7 File-creation investigation (Event ID 11)

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=11
| rex field=_raw "<Data Name='TargetFilename'>(?<TargetFilename>.*?)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessID>.*?)</Data>"
| where like(TargetFilename,"%AttackLab%")
| table _time ProcessID TargetFilename
| sort -_time
```

![Attack simulation file creation](docs/images/23__Attack_Simulation_File_Creation.png)
*Figure 11 – Four file events under `AttackLab`.*

| Time | PID | TargetFilename |
|---|---|---|
| 12:55:03.981 | 13208 | `…\AttackLab\remote_execution_marker.txt` |
| 12:54:18.365 | 1680 | `…\AttackLab\lab_simulation.ps1` |
| 12:51:14.223 | 1680 | `…\AttackLab\lab_payload.txt` |
| 12:51:06.760 | 1680 | `…\AttackLab` (directory) |

The earlier validation file was also recorded:

![File creation process investigation](docs/images/6__file-creation-process-investigation.png)
*Figure 12 – `invoice_update.txt` created by PID 1680 (`Windows11\joshn`) at 11:35:14.199.*

**[Observed – to verify]** Sysmon recorded creation at 11:35:14, while the file's `LastWriteTime` in Figure 4 is 11:37 — consistent with creation followed by a later rewrite, but not confirmed.

## 8. Detection Engineering and SPL Queries

### 8.1 Detection A – PowerShell network connection

**Logic:** PowerShell making outbound connections is uncommon for most user workstations and is a common download/C2 pattern.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=3
| rex field=_raw "<Data Name='Image'>(?<Image>.*?)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIP>.*?)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>.*?)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessID>.*?)</Data>"
| where match(Image,"(?i)\\\\powershell\.exe$")
| eval Detection="PowerShell Network Connection"
| table _time host Detection Image ProcessID DestinationIP DestinationPort
| sort -_time
```

**Expected output:** one row per PowerShell connection. At the time of testing it returned one event (host `Windows11`, PID 1680 → 104.20.23.154:443 at 12:12:01.998).
**Saved as:** report *"PowerShell Network Connection Detection"*.

![Detection – PowerShell network connection](docs/images/14__Detection_PowerShell_Network_Connection.png)
![Saved PowerShell network detection report](docs/images/15__Saved_PowerShell_Network_Detection_Report.png)

### 8.2 Detection B – Kali-to-Windows transfer and script execution

**Logic:** combine a network event to the attacker host/port with a process event running a script from the `AttackLab` directory, so one search shows *transfer → execution*.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1 OR EventCode=3
| rex field=_raw "<Data Name='Image'>(?<Image>.*?)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessID>.*?)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIP>.*?)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>.*?)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>.*?)</Data>"
| eval Activity=case(EventCode="3","Network connection",EventCode="1","Process execution")
| where (EventCode="3" AND DestinationIP="172.16.217.129" AND DestinationPort="8000")
     OR (EventCode="1" AND match(CommandLine,"(?i)AttackLab\\\\.*\.ps1"))
| table _time Activity Image ProcessID DestinationIP DestinationPort CommandLine
| sort _time
```

**Expected output / observed:** 3 events in the last-60-minute window — two connections to 172.16.217.129:8000 (12:51:15.932, 12:54:19.469) and one process execution (PID 13208, 12:55:01.337).
**Saved as:** *"Kali-to-Windows Transfer and Script Execution Detection"*.

![Network and execution correlation](docs/images/21__Detection_Network_Execution_Correlation.png)

**Caveat:** this rule hard-codes the lab's attacker IP, port and folder name. It proves the pipeline works for this scenario; it is not a generalisable detection (see 10.4).

### 8.3 Detection C – Suspicious PowerShell arguments

```spl
... | search EventCode=1
| rex field=_raw "<Data Name='Image'>(?<Image>.*?)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>.*?)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>.*?)</Data>"
| where match(Image,"(?i)\\\\powershell\.exe$")
| where match(CommandLine,"(?i)(-encodedcommand|-enc\\s|-windowstyle hidden|-w hidden|-nop\\b)")
| eval Detection="Suspicious PowerShell Arguments"
| table _time host Detection Image ParentImage CommandLine
| sort -_time
```

![Suspicious arguments – no matches](docs/images/13__PowerShell_Suspicious_Arguments_No_Matches.png)
*Figure 13 – 0 events.*

**[Observed]** zero results.
**[Interpretation]** see 9.4: this is a correct negative for encoded/hidden-window usage, but the pattern also fails to match the `-NoProfile -ExecutionPolicy Bypass` command lines that *did* occur in the lab.

**Proposed refinement (untested):**

```spl
| where match(CommandLine,"(?i)(-e(nc(odedcommand)?)?\\s|-w(indowstyle)?\\s+hidden|-nop(rofile)?\\b|-ep\\s+bypass|-executionpolicy\\s+bypass)")
```

`-NoProfile` alone is common in admin scripts, so in production this should be scored in combination (e.g. Bypass + script path from a user-writable folder + parent is an interactive shell).

### 8.4 MITRE ATT&CK mapping (analytical interpretation)

| Lab activity | Technique |
|---|---|
| Nmap service scan | T1046 Network Service Discovery |
| Pulling files from Kali over HTTP | T1105 Ingress Tool Transfer |
| PowerShell script execution | T1059.001 Command and Scripting Interpreter: PowerShell |

## 9. Results and Discussion

### 9.1 Evidence summary

| # | Finding | Evidence | Status |
|---|---|---|---|
| 1 | Windows host 172.16.217.130 exposes RPC, NetBIOS, SMB, PostgreSQL and Splunk ports | Fig. 3 | Observed |
| 2 | Kali at 172.16.217.129 served files on TCP/8000 | Fig. 2, Fig. 13 (EID 3 to :8000) | Observed |
| 3 | PowerShell PID 1680 connected to Kali twice (12:51:15, 12:54:19) | Detection B | Observed |
| 4 | Files created in `AttackLab` by PID 1680 immediately around those connections | Fig. 11 | Observed |
| 5 | Child PowerShell PID 13208 executed `lab_simulation.ps1` with `-ExecutionPolicy Bypass` | Fig. 9, 10 | Observed |
| 6 | PID 13208 created `remote_execution_marker.txt` ~2.6 s later | Fig. 11 | Observed |
| 7 | Process lineage resolved through GUIDs, not just PIDs | Fig. 7, 8 | Observed |
| 8 | Script spawned no child processes | Fig. 10 | Observed (within queried window) |
| 9 | Transfer and execution form one download-then-execute chain | Findings 3–6 | Interpretation |
| 10 | Suspicious-argument search returned 0 matches | Fig. 13 | Observed |

### 9.2 What the correlation shows

**[Interpretation]** Each event class alone is ambiguous: a network connection to a private IP is routine, a `.ps1` file creation is routine, and a PowerShell launch is routine. The chain — *same parent PID 1680 → connection to the attacker host → file written → child PowerShell runs that file → marker written* — is what distinguishes this from background activity. This is the core contribution of the project.

### 9.3 Why GUIDs matter

PIDs are recycled by Windows. Correlating on `ProcessGuid` / `ParentProcessGuid` guarantees that the 1680 in the network events, file events and process-creation events is the same instance. (The execution searches in this lab still used PIDs for convenience; GUID-based joins would be the more robust form.)

### 9.4 The zero-match result is a detection gap, not just a clean result

**[Observed]** The suspicious-argument search (Fig. 13) was run at about 12:21 with *All time*. At that time, `PID 4328` (11:26:26) had already run with `-NoProfile -ExecutionPolicy Bypass`.
**[Interpretation]** The pattern contains `-nop\b`, which does not match `-NoProfile` (no word boundary between `p` and `r`), and it contains no `ExecutionPolicy Bypass` clause. The rule therefore would not have fired even on the lab's own benign script. Negative results from detection rules should be validated against a known-positive test case before being trusted.

### 9.5 Baseline vs. suspicious behaviour

The same parent process legitimately launched `sc.exe` and `netstat.exe` (Section 7.4). Detections should reason about *combinations* (parent, command line, destination, file path), not single indicators.

## 10. Limitations

1. **Single endpoint, single scenario.** One victim, one short run; no statistics, detection rates or false-positive rates are claimed.
2. **Splunk co-located with the victim.** The Nmap scan and Splunk process queries show Splunk on the Windows host itself. An attacker with admin rights could tamper with the SIEM or Sysmon. Production design separates forwarder, indexer and endpoint.
3. **Interactive commands are not visible in Sysmon.** Sysmon records child processes, connections and files, but not the PowerShell cmdlets typed inside session 1680 (e.g. the download command). PowerShell Script Block Logging (Event ID 4104) and Module Logging would be required.
4. **Hard-coded detections.** Detection B uses lab-specific IP, port and path.
5. **Raw-XML `rex` parsing.** Works for the lab but is fragile and slow versus a proper Sysmon add-on with CIM-compliant field extraction.
6. **Not an isolated network** (Section 4.3).
7. **Timestamp ordering.** File events preceded matching network events by 1–2 s; time source not yet validated.
8. **No attack-success telemetry.** There is no exploit, no persistence, no lateral movement and no evasion, so the lab does not test whether detections survive an adversary.
9. **Gaps in evidence.** Sysmon version/config, ingestion method, script body, download commands, dashboard screenshots and the PostgreSQL service owner are not documented here (`TODO`).

## 11. Conclusion and Future Scope

The lab demonstrates that Sysmon Event IDs 1, 3 and 11 together, joined in Splunk, are enough to reconstruct a download-then-execute chain from the attacker host to a marker file on the endpoint, including parent–child lineage, without relying on a single log source. It also showed, through the zero-match result, that detection logic needs test cases and iteration.

**Realistic next steps**

1. Enable PowerShell Script Block Logging (4104) and ingest it, so the actual download commands are visible.
2. Use a Splunk-supported Sysmon add-on and a Universal Forwarder on a **separate** Splunk host.
3. Rewrite Detection B to be generic: *PowerShell connection to an internal/unusual IP followed by script execution from a user-writable path within N minutes*, joined on `ProcessGuid`.
4. Fix and regression-test Detection C using the lab's own command lines as known positives and benign admin usage as negatives.
5. Add alerts (scheduled searches with throttling) and map detections to ATT&CK in a table.
6. Add Sysmon Event ID 22 (DNS) and Security 4688/4104 to widen coverage.
7. Introduce additional benign techniques (scheduled task creation, registry run key) and measure which are detected.
8. Run the same scenario with Defender active and document what it sees versus Sysmon.

### Dashboard

> `TODO`: add dashboard screenshots (event volume, process activity, network connections, process lineage, file creation).

![Dashboard overview](docs/images/dashboard_overview.png)
![Dashboard process lineage](docs/images/dashboard_process_lineage.png)
![Dashboard network and file activity](docs/images/dashboard_network_file.png)

## 12. References

- Microsoft Sysinternals – Sysmon documentation and event reference.
- Splunk Enterprise documentation – `rex`, `eval`, `where`, saved searches and dashboards.
- Nmap Reference Guide – service/version detection (`-sV`) and `-Pn`.
- MITRE ATT&CK – T1046, T1059.001, T1105.
- Microsoft documentation – PowerShell execution policies and Script Block Logging.
- Python documentation – `http.server`.
