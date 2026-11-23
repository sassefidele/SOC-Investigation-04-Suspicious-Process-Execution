# SOC Investigation #004 — Suspicious Process Execution and Parent-Child Process Analysis

**Windows Sysmon Event ID 1 · Windows Security Event ID 4688 · Wazuh SIEM · Cross-source correlation**

> **Result: Detection validation PASS. Analyst disposition: Benign, authorized lab test.** The word “suspicious” refers to the Wazuh detection descriptions, not a confirmed attack.

## Executive summary

On November 23, 2026, a controlled Windows 11 lab test launched `cmd.exe` from `powershell.exe`, then `whoami.exe` from `cmd.exe`. Sysmon Event ID 1 and Windows Security Event ID 4688 independently recorded both child processes. The Wazuh manager received matching Sysmon events and produced rules **92004** and **92032**. Matching process IDs, parent process relationships, timestamps, and a unique test marker support the correlation. No unauthorized or malicious activity was established.

## Lab environment

| Component | Role |
|---|---|
| `SOC-WIN11-01` | Windows 11 ARM64 endpoint |
| Sysmon (`Sysmon64a`) | Process creation telemetry, Event ID 1 |
| Windows Security auditing | Process creation, Event ID 4688 |
| Wazuh Windows agent (`WazuhSvc`) | Forwards endpoint telemetry |
| `wazuh-siem-01` | Ubuntu-based Wazuh manager / SIEM |
| VMware Fusion | Virtualization platform |

## Controlled test

Executed in PowerShell on the owned lab endpoint:

```powershell
$LabMarker = "SOC-INV-004-PROCESS-CHAIN"
Write-Output "Starting $LabMarker"
cmd.exe /c "echo SOC-INV-004-PROCESS-CHAIN && whoami.exe"
Write-Output "Test completed"
```

**Observed process tree:**

```text
powershell.exe (PID 10080 / 0x2760)
└── cmd.exe (PID 5376 / 0x1500)
    └── whoami.exe (PID 10524 / 0x291c)
```

## Correlated evidence

| Source | Evidence | Outcome |
|---|---|---|
| Sysmon Event ID 1 | `cmd.exe`, PID 5376; parent `powershell.exe`, PID 10080 | Confirmed |
| Sysmon Event ID 1 | `whoami.exe`, PID 10524; parent `cmd.exe`, PID 5376 | Confirmed |
| Windows Security Event ID 4688 | `cmd.exe`, PID `0x1500`; creator PID `0x2760` | Confirmed |
| Windows Security Event ID 4688 | `whoami.exe`, PID `0x291c`; creator PID `0x1500` | Confirmed |
| Wazuh Rule 92004 | “Powershell process spawned Windows command shell instance” (`cmd.exe`) | Alert observed |
| Wazuh Rule 92032 | “Suspicious Windows cmd shell execution” (`whoami.exe`) | Alert observed |

Both Windows event providers recorded the test at **2026-11-23 08:59:07 local time**. Wazuh alerts were timestamped approximately **2026-11-23 16:59:08 UTC**. The unique marker `SOC-INV-004-PROCESS-CHAIN` appears in the `cmd.exe` command line and the `whoami.exe` parent command line.

Sysmon process GUID linkage independently supports `cmd.exe` → `whoami.exe`: the `cmd.exe` ProcessGuid matched `whoami.exe` ParentProcessGuid.

## Screenshot evidence

1. [Service verification](screenshots/01-Sysmon-Wazuh-Service-Verification.png) — Sysmon running, recent Event ID 1 entries, Wazuh agent running.
2. [Sysmon `whoami.exe` event](screenshots/02-Sysmon-Whoami-Process-Creation.png) — PID, parent PID, image and command line.
3. [Sysmon `cmd.exe` event](screenshots/03-Sysmon-Cmd-Process-Creation.png) — PowerShell parent and unique test marker.
4. [Wazuh alerts](screenshots/04-Wazuh-Process-Execution-Alerts.png) — Rule 92004 and rule 92032 records.
5. [Security Event 4688 correlation](screenshots/05-Windows-Event-4688-Correlation.png) — Matching hexadecimal PIDs and parent process relationships.

## Analyst assessment

The events are consistent with the explicitly authorized lab command. Wazuh classified the behavior under detection rules, but a rule firing does not prove compromise. The observed user context was `SOC-WIN11-01\socadmin`, and Sysmon indicated high integrity. No evidence was presented of persistence, unauthorized access, payload delivery, or an external attacker.

**Disposition:** Benign / expected test activity. **Escalation:** Not warranted for this specific controlled test. In a production incident, investigate initiating user, process ancestry, executable signatures, hashes, command-line intent, surrounding authentication events, and other host activity before making a determination.

## Full investigation report

See [Investigation-04-Suspicious-Process-Execution.md](reports/Investigation-04-Suspicious-Process-Execution.md).

## Skills demonstrated

Sysmon process analysis · Windows Security auditing · Parent-child process reconstruction · PID and GUID correlation · Wazuh rule triage · SIEM evidence collection · Benign-versus-suspicious assessment · Technical reporting.

## Scope and limitations

This is a personally controlled educational lab, not a production incident. The screenshots show the observed state at collection time. This exercise validates selected process-creation detections; it does not establish that all process execution is monitored or that every suspicious execution would alert. Screenshots may expose local account names and lab-only identifiers; review before public publication.
