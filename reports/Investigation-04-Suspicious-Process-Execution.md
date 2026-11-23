# SOC Investigation Report #004

**Case title:** Suspicious Process Execution and Parent-Child Process Analysis  
**Date:** November 23, 2026  
**Endpoint:** `SOC-WIN11-01`  
**SIEM:** Wazuh on `wazuh-siem-01`  
**Status:** Closed — benign authorized test; detection validation PASS

## 1. Purpose and scope

Validate whether an intentionally generated Windows process chain is recorded by Sysmon and Windows Security auditing, forwarded to Wazuh, and classified by the available detection rules. Reconstruct the parent-child relationships using independent event fields. No malicious payload or unauthorized action was involved.

## 2. Test activity

The operator executed a harmless command from an elevated PowerShell session:

```powershell
$LabMarker = "SOC-INV-004-PROCESS-CHAIN"
Write-Output "Starting $LabMarker"
cmd.exe /c "echo SOC-INV-004-PROCESS-CHAIN && whoami.exe"
Write-Output "Test completed"
```

This launched `cmd.exe` and then `whoami.exe`. The marker permits matching the specific test to process-creation logs.

## 3. Timeline

| Time | Event | Source |
|---|---|---|
| 2026-11-23 08:59:07 local | `powershell.exe` launches `cmd.exe` (PID 5376) | Sysmon Event 1 / Security Event 4688 |
| 2026-11-23 08:59:07 local | `cmd.exe` launches `whoami.exe` (PID 10524) | Sysmon Event 1 / Security Event 4688 |
| 2026-11-23 16:59:08 UTC | Rule 92004 alert for PowerShell spawning command shell | Wazuh `alerts.json` |
| 2026-11-23 16:59:08 UTC | Rule 92032 alert for suspicious cmd shell execution | Wazuh `alerts.json` |

The displayed Wazuh alert timestamps are approximately one second after the Windows local event time when converted to UTC. This supports event correlation, but does not measure precise network or detection latency.

## 4. Endpoint evidence

**Sysmon Event ID 1:**

| Field | `cmd.exe` | `whoami.exe` |
|---|---|---|
| Process ID | 5376 | 10524 |
| Parent Process ID | 10080 | 5376 |
| Parent image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `C:\Windows\System32\cmd.exe` |
| User | `SOC-WIN11-01\socadmin` | `SOC-WIN11-01\socadmin` |
| Integrity level | High | High |

**Windows Security Event ID 4688:**

| Field | `cmd.exe` | `whoami.exe` |
|---|---|---|
| New process ID (hex) | `0x1500` | `0x291c` |
| Creator process ID (hex) | `0x2760` | `0x1500` |
| New process ID (decimal) | 5376 | 10524 |
| Creator process ID (decimal) | 10080 | 5376 |
| Token elevation type | Full (2) | Full (2) |

The numeric IDs and parent image names agree across Sysmon and Windows Security logs. In Sysmon, the `cmd.exe` ProcessGuid was `{949de23b-70db-6b04-6420-000000001800}` and matched the `whoami.exe` ParentProcessGuid, strengthening process identity correlation beyond PID alone.

## 5. Wazuh detections

The Wazuh manager alert log returned two matching records for agent `SOC-WIN11-01` and Sysmon Event ID 1:

- **Rule 92004:** “Powershell process spawned Windows command shell instance”; child image `cmd.exe`, parent image `powershell.exe`.
- **Rule 92032:** “Suspicious Windows cmd shell execution”; child image `whoami.exe`, parent image `cmd.exe`.

The `cmd.exe` command line included `SOC-INV-004-PROCESS-CHAIN`; the `whoami.exe` event included the same marker in `parentCommandLine`. These observations link the Wazuh alerts to the deliberate test. The screenshot shows the alert records but does not establish an additional MITRE ATT&CK technique mapping for these two specific alerts; no unsupported mapping is asserted here.

## 6. Analysis and disposition

The process ancestry and command lines are exactly what the operator intended to generate. Although command interpreters and identity discovery utilities can appear in malicious workflows, their presence alone is insufficient to infer malicious intent. The observed process sequence was benign and authorized.

**Analyst disposition:** Benign test / no escalation.  
**Detection result:** PASS for this particular process chain and two Wazuh rules.  
**Incident determination:** No evidence of compromise in the supplied telemetry.

## 7. Limitations and recommended follow-up

- The test was limited to a single endpoint, one short process chain, and a narrow time window.
- `alerts.json` contains alert-generating records and is not a complete record of all collected events.
- No broader threat-hunting sweep or independent forensic imaging was performed.
- A production investigation should review executable reputation, signatures, hashes, user authorization, surrounding events, process ancestry, and host baselines.
- The test does not demonstrate prevention or blocking; it demonstrates detection and investigation.

## 8. Evidence index

| ID | Screenshot | Purpose |
|---|---|---|
| E01 | `screenshots/01-Sysmon-Wazuh-Service-Verification.png` | Service status and local Sysmon availability |
| E02 | `screenshots/02-Sysmon-Whoami-Process-Creation.png` | Sysmon `whoami.exe` event and `cmd.exe` parent |
| E03 | `screenshots/03-Sysmon-Cmd-Process-Creation.png` | Sysmon `cmd.exe` event and PowerShell parent |
| E04 | `screenshots/04-Wazuh-Process-Execution-Alerts.png` | Wazuh rules 92004 and 92032 |
| E05 | `screenshots/05-Windows-Event-4688-Correlation.png` | Security Event 4688 PID correlation |

*Paths above are relative to the repository root.*
