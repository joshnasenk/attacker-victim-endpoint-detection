# Attacker–Victim Simulation and Endpoint Threat Detection with Sysmon and Splunk

A two-VM lab (Kali Linux → Windows 11 ARM64) that generates endpoint and network telemetry with Sysmon, ingests it into Splunk Enterprise, and uses SPL to reconstruct and detect a controlled download-then-execute chain.

> **Scope.** The simulation is benign. It does not use malware or Meterpreter, does not open a reverse shell, does not disable Defender and does not perform post-exploitation. The focus is telemetry, correlation and detection engineering.



[SOC Lab Monitoring Dashboard.pdf](https://github.com/user-attachments/files/35156382/SOC.Lab.Monitoring.Dashboard.pdf)

---

## Contents

- [Architecture](#architecture)
- [Environment](#environment)
- [Simulation steps](#simulation-steps)
- [Telemetry: Sysmon events used](#telemetry-sysmon-events-used)
- [Investigation walkthrough](#investigation-walkthrough)
- [Reconstructed timeline and process tree](#reconstructed-timeline-and-process-tree)
- [Detections](#detections)
- [Dashboard](#dashboard)
- [Results](#results)
- [Limitations](#limitations)
- [Future work](#future-work)
- [ATT&CK mapping](#attck-mapping)

---

## Architecture

<img width="759" height="447" alt="project workflow" src="https://github.com/user-attachments/assets/6509df1e-cb5e-4f82-9cd4-4476a19b23d0" />

<img width="1510" height="897" alt="1  vmware-lab-architecture" src="https://github.com/user-attachments/assets/3fd49394-0d18-40dc-902d-52229911bfd2" />




## Environment

| Component | Details |
|---|---|
| Host | macOS, VMware Fusion |
| Attacker | Kali Linux, `eth0` 172.16.217.129/24 |
| Victim | Windows 11 ARM64, hostname `Windows11`, 172.16.217.130 |
| Telemetry | Microsoft Sysmon → `Microsoft-Windows-Sysmon/Operational` |
| SIEM | Splunk Enterprise 10.4.2 (runs on the Windows VM) |
| Index / sourcetype | `index=main`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Tools | Nmap 7.99, Python `http.server`, Windows PowerShell 5.1 |

Both VMs share the 172.16.217.0/24 virtual subnet. The Windows VM also reaches the internet (Edge, OneDrive and PowerShell make outbound connections), so the lab is not air-gapped.

<img width="687" height="515" alt="2  kali-ip-configuration" src="https://github.com/user-attachments/assets/1ad9d7eb-d740-4b53-9224-a5c0d0bed0ab" />


## Simulation steps

### 1. Reconnaissance

```bash
nmap -sV -Pn 172.16.217.130
```

`-Pn` skips host discovery (Windows Firewall commonly drops ping); `-sV` fingerprints services.

<img width="647" height="418" alt="3  nmap-service-discovery" src="https://github.com/user-attachments/assets/0256850e-950f-4b4c-9685-854ec442daa1" />


| Port | Service | Version |
|---|---|---|
| 135/tcp | msrpc | Microsoft Windows RPC |
| 139/tcp | netbios-ssn | Microsoft Windows netbios-ssn |
| 445/tcp | microsoft-ds | SMB |
| 5432/tcp | postgresql | PostgreSQL DB |
| 8000/tcp | http | Splunkd httpd |
| 8089/tcp | ssl/http | Splunkd httpd |

994 closed ports; scan time 34 s; MAC `00:0C:29:67:F7:90` (VMware).

### 2. Controlled file transfer

Kali serves a benign payload and a benign script:

```bash
python3 -m http.server 8000
```

Windows pulls both files from `172.16.217.129:8000` using PowerShell into `C:\Users\joshn\Desktop\AttackLab\`. The browser tab "Directory listing for /" in the captures is the Python server's index page.

Before the transfer, a local file was created on Windows to validate Sysmon file-event logging:

```powershell
Set-Content -Path "$env:USERPROFILE\Desktop\LabTest\Incoming\invoice_update.txt" -Value "BENIGN SECURITY LAB TEST"
```

<img width="897" height="507" alt="4  file-delivery-windows" src="https://github.com/user-attachments/assets/a80bf41f-fcb9-4adf-97b6-ee24f02bddca" />


### 3. Script execution

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\joshn\Desktop\AttackLab\lab_simulation.ps1
```

The script only writes `remote_execution_marker.txt`, which gives a clean, observable end of the chain.

## Telemetry: Sysmon events used

| Event ID | Event | Why it matters | Fields used |
|---|---|---|---|
| 1 | Process creation | What ran, with full command line and parent | `Image`, `ProcessId`, `ProcessGuid`, `ParentProcessId`, `ParentProcessGuid`, `CommandLine` |
| 3 | Network connection | Ties a connection to the process that made it | `Image`, `ProcessId`, `SourceIp`, `DestinationIp`, `DestinationPort`, `Protocol` |
| 11 | File create | What a process wrote to disk | `TargetFilename`, `ProcessId`, `Image`, `User` |

Events are indexed as raw XML, so fields are extracted at search time with `rex`. Process GUIDs are used for lineage because Windows reuses PIDs, while a GUID identifies one process instance.

## Investigation walkthrough

All times are IST (UTC+05:30).

### Network baseline (EID 3)

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

<img width="1512" height="833" alt="8  Sysmon_Network_Connection_Analysis" src="https://github.com/user-attachments/assets/2555b34e-700b-4126-b8ee-e7035de756a4" />


108 connection events in the baseline view, mostly background traffic: OneDrive `FileCoAuth.exe`, `msedge.exe` (including IPv6 multicast) and PowerShell. Filtering by process image is what separates the signal.

### Narrowing to PowerShell PID 1680

Adding `| search ProcessID=1680` returns PowerShell's connection to 104.20.23.154:443 at 12:12:01.998.

<img width="1512" height="830" alt="9  PowerShell_Network_Connection_Correlation" src="https://github.com/user-attachments/assets/a0640635-4634-4a40-b569-3524874e37cf" />


### Process GUID and parent

```spl
... | search EventCode=1
| rex field=_raw "<Data Name='ProcessGuid'>(?<ProcessGuid>.*?)</Data>"
| rex field=_raw "<Data Name='ParentProcessGuid'>(?<ParentProcessGuid>.*?)</Data>"
| search ProcessID=1680
| table _time Image ProcessID ProcessGuid ParentProcessGuid
```

<img width="1511" height="831" alt="11  Sysmon_ProcessGuid_Correlation" src="https://github.com/user-attachments/assets/d74f81a0-3ea7-4707-b571-87aa3fd6f414" />


PID 1680 started at 09:52:33.447 with `ProcessGuid {b46cdb52-cb09-6aff-888f-010000000800}`, parent PID 4800.

### Children of PID 1680

```spl
... | search ParentProcessGuid="{b46cdb52-cb09-6aff-888f-010000000800}"
| table _time Image ProcessID CommandLine
| sort _time
```

<img width="1512" height="833" alt="12  Sysmon_Child_Process_Investigation" src="https://github.com/user-attachments/assets/68f23bb0-cfd1-4d27-8459-40bb6034138e" />


Seven child processes. The earliest are routine checks by the same session: `sc.exe queryex Splunkd`, `NETSTAT.EXE -ano`, `findstr.exe :8000`. This is the legitimate baseline for that parent.

### Script executions

```spl
... | where match(CommandLine,"(?i)simulation\.ps1")
| table _time Image ProcessID ParentProcessID CommandLine
| sort -_time
```

<img width="1512" height="982" alt="22  Attack_Simulation_Process_Creation" src="https://github.com/user-attachments/assets/ab77af12-e1f4-4bec-8028-4c8312148ff4" />


Three runs, all with parent PID 1680: PID 7400 (11:25:53) and PID 4328 (11:26:26) from `LabTest`, and PID 13208 (12:55:01) from `AttackLab`.

```spl
... | where ProcessID="13208" OR ParentProcessID="13208" OR ProcessID="1680"
| table _time Image ProcessID ParentProcessID CommandLine
| sort _time
```

<img width="1512" height="982" alt="24  Attack_Simulation_Process_Parent_Child" src="https://github.com/user-attachments/assets/f0a0823a-60b6-4e3b-a81a-dab261a45b03" />


No process has `ParentProcessID=13208`, so the script spawned no children.

### File creation (EID 11)

```spl
... | search EventCode=11
| rex field=_raw "<Data Name='TargetFilename'>(?<TargetFilename>.*?)</Data>"
| rex field=_raw "<Data Name='ProcessId'>(?<ProcessID>.*?)</Data>"
| where like(TargetFilename,"%AttackLab%")
| table _time ProcessID TargetFilename
| sort -_time
```

<img width="1512" height="982" alt="23  Attack_Simulation_File_Creation" src="https://github.com/user-attachments/assets/6e0289b2-8382-4504-831c-c44a46375d9b" />


The earlier validation file is also recorded (`invoice_update.txt`, PID 1680, user `Windows11\joshn`, 11:35:14.199):

<img width="1512" height="833" alt="12  Sysmon_Child_Process_Investigation" src="https://github.com/user-attachments/assets/93a59712-7a8e-40d4-a180-00f15c090409" />


## Reconstructed timeline and process tree

| Time | EID | Process | Event |
|---|---|---|---|
| 09:52:33.447 | 1 | powershell.exe 1680 (parent 4800) | Interactive session starts |
| 12:12:01.998 | 3 | powershell.exe 1680 | → 104.20.23.154:443 |
| 12:51:06.760 | 11 | powershell.exe 1680 | `AttackLab` directory created |
| 12:51:14.223 | 11 | powershell.exe 1680 | `lab_payload.txt` created |
| 12:51:15.932 | 3 | powershell.exe 1680 | → 172.16.217.129:8000 (Kali) |
| 12:54:18.365 | 11 | powershell.exe 1680 | `lab_simulation.ps1` created |
| 12:54:19.469 | 3 | powershell.exe 1680 | → 172.16.217.129:8000 (Kali) |
| 12:55:01.337 | 1 | powershell.exe 13208 (parent 1680) | Runs `lab_simulation.ps1` with `-ExecutionPolicy Bypass` |
| 12:55:03.981 | 11 | powershell.exe 13208 | `remote_execution_marker.txt` created |

```
PID 4800
└─ powershell.exe 1680   09:52:33  {b46cdb52-cb09-6aff-888f-010000000800}
   ├─ sc.exe        15644  10:19:21  queryex Splunkd
   ├─ NETSTAT.EXE   15068  10:19:27  -ano
   ├─ findstr.exe    3564  10:19:27  :8000
   ├─ NETSTAT.EXE    4160  ~10:25    -ano
   ├─ powershell.exe 7400  11:25:53  -File ...\LabTest\simulation.ps1
   ├─ powershell.exe 4328  11:26:26  -NoProfile -ExecutionPolicy Bypass -File ...\LabTest\simulation.ps1
   └─ powershell.exe 13208 12:55:01  -NoProfile -ExecutionPolicy Bypass -File ...\AttackLab\lab_simulation.ps1
```

The last three children follow from the script-execution searches; the child-process capture shows only the first four of the seven rows.

File events are stamped 1–2 s before the matching network events in both transfers, so sub-second ordering between event types shouldn't be over-interpreted.

## Detections

### A. PowerShell network connection

PowerShell making outbound connections is unusual on most workstations and is a common download/C2 pattern.

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

Saved as *PowerShell Network Connection Detection*. At first run it returned one event (host `Windows11`, PID 1680 → 104.20.23.154:443). Re-run after the transfer, it also returns both connections to Kali.

<img width="1512" height="831" alt="14  Detection_PowerShell_Network_Connection" src="https://github.com/user-attachments/assets/79bc876a-80fd-4bc3-b06e-5cdebb022a81" />


<img width="1512" height="829" alt="15  Saved_PowerShell_Network_Detection_Report" src="https://github.com/user-attachments/assets/21ed828c-406c-46e2-81b2-11a63bf4eea3" />


### B. Kali-to-Windows transfer followed by script execution

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

Saved as *Kali-to-Windows Transfer and Script Execution Detection*. Returns three rows: two connections to 172.16.217.129:8000 and the PID 13208 execution. The IP, port and folder are hard-coded to this lab, so it validates the pipeline rather than serving as a general-purpose rule.

<img width="1512" height="982" alt="21  Detection_Network_Execution_Correlation" src="https://github.com/user-attachments/assets/cfba3e2c-ea36-4e95-959b-253da462524f" />


### C. Suspicious PowerShell arguments, and a gap

```spl
... | search EventCode=1
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>.*?)</Data>"
| where match(Image,"(?i)\\\\powershell\.exe$")
| where match(CommandLine,"(?i)(-encodedcommand|-enc\\s|-windowstyle hidden|-w hidden|-nop\\b)")
| eval Detection="Suspicious PowerShell Arguments"
| table _time host Detection Image ParentImage CommandLine
| sort -_time
```

<img width="1511" height="831" alt="13  PowerShell_Suspicious_Arguments_No_Matches" src="https://github.com/user-attachments/assets/bde1954c-a0be-455d-83cf-46c1c56fc844" />


It returned 0 events, but PID 4328 had already run with `-NoProfile -ExecutionPolicy Bypass` at 11:26. The pattern uses `-nop\b`, which does not match `-NoProfile` (no word boundary between `p` and `r`), and it has no `ExecutionPolicy Bypass` clause. The rule would have missed the lab's own script. Proposed refinement (not yet tested):

```spl
| where match(CommandLine,"(?i)(-e(nc(odedcommand)?)?\\s|-w(indowstyle)?\\s+hidden|-nop(rofile)?\\b|-ep\\s+bypass|-executionpolicy\\s+bypass)")
```

`-NoProfile` alone is common in admin scripts, so in production this should be combined with other signals (Bypass plus a script path in a user-writable folder, launched from an interactive shell).

## Dashboard

*SOC Lab Monitoring Dashboard* (Splunk, time range: All time).

| Panel | Shows |
|---|---|
| PowerShell Network Connections | 3 rows: two to 172.16.217.129:8000 (12:51:15, 12:54:19) and one to 104.20.23.154:443 (12:12:01) |
| Total Sysmon Events | 58,444 events ingested |
| Sysmon Event Volume by Event ID | EID 11 (file create) dominates at roughly 50K, followed by 10, 1, 25, 7, 13, 2, 3, 22 and others |
| Process Creation Activity Over Time | EID 1 counts in 5-minute bins; steady ~30–40 per bin, a peak near 64 in the morning, and a sharp drop from about 1:00 PM that recovers around 3:00 PM |
| Top destination IPs | Connections per destination; 172.16.217.1 and an `fe80::` link-local address lead at about 60 each, followed by low counts to public addresses |
| Kali-to-Windows HTTP Transfer Activity | `powershell.exe` 172.16.217.130 → 172.16.217.129:8000, 2 connections, first 12:51:15.932, last 12:54:19.469 |
| Controlled Simulation – Process Lineage | PID 1680 (parent 4800) and PID 13208 (parent 1680) with command lines |
| AttackLab File Creation Activity | The four file events listed in the timeline |

Notes on the data: Splunk runs on the same host that produces the logs, so file-create volume likely includes Splunk's own disk activity. The process-creation drop was not investigated further.

## Results

| # | Finding | Evidence |
|---|---|---|
| 1 | Windows host exposes RPC, NetBIOS, SMB, PostgreSQL and Splunk ports | Nmap |
| 2 | PowerShell 1680 connected to the Kali server twice (12:51:15, 12:54:19) | Detection A/B, dashboard |
| 3 | The same process created `AttackLab`, `lab_payload.txt` and `lab_simulation.ps1` around those connections | EID 11 |
| 4 | Child PowerShell 13208 executed the downloaded script with `-ExecutionPolicy Bypass` | EID 1 |
| 5 | PID 13208 created `remote_execution_marker.txt` 2.6 s after starting | EID 11 |
| 6 | The script spawned no child processes | Parent-child check |
| 7 | Lineage was resolved with Process GUIDs, not just PIDs | EID 1 |
| 8 | The suspicious-argument rule produced a false negative against the lab's own script | Detection C analysis |

The central result is the correlation. A private-IP connection, a `.ps1` file creation and a PowerShell launch are each ordinary on their own. Joined by parent process, they show a single chain: connect to the attacker host, write files, launch a child that runs the written script.

## Limitations

- **One endpoint, one scenario.** No detection rates or false-positive rates are claimed.
- **Splunk and Sysmon share the victim VM.** An attacker with admin rights could tamper with either. Production separates forwarder, indexer and endpoint.
- **Typed PowerShell commands are not visible.** Sysmon records child processes, connections and files, not the cmdlets entered inside session 1680, including the download itself. Script Block Logging (EID 4104) would cover it.
- **Hard-coded detection B.** It depends on this lab's IP, port and folder name.
- **`rex` on raw XML.** Fine for a lab, but slower and more fragile than a Sysmon add-on with proper field extraction.
- **Not air-gapped.** The VM has internet access.
- **No adversary pressure.** No evasion, persistence or lateral movement, so the detections are not tested against an adaptive attacker.

## Future work

1. Enable and ingest PowerShell Script Block Logging (4104).
2. Move Splunk to a separate host with a Universal Forwarder and the Sysmon add-on.
3. Generalise Detection B: PowerShell connecting to an internal or unusual IP, followed by script execution from a user-writable path within a time window, joined on `ProcessGuid`.
4. Regression-test Detection C using the lab's command lines as known positives.
5. Add scheduled alerts with throttling.
6. Add Sysmon EID 22 (DNS) and further benign techniques such as scheduled tasks and Run keys.
7. Compare what Windows Defender reports against what Sysmon captures for the same scenario.

## ATT&CK mapping

| Activity | Technique |
|---|---|
| Nmap service scan | T1046 Network Service Discovery |
| Files pulled from Kali over HTTP | T1105 Ingress Tool Transfer |
| PowerShell script execution | T1059.001 Command and Scripting Interpreter: PowerShell |
