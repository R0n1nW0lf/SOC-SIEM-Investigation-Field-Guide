# SOC/SIEM Investigation Field Guide

A practical SOC/SIEM investigation field guide developed from hands-on security labs and investigation exercises.

## About This Project

This field guide documents my approach to investigating security alerts, analyzing logs, identifying attack indicators, determining whether an attack was successful, and making escalation and containment decisions.

The guide is designed as a quick-reference resource for SOC investigations and will continue to grow as I complete additional hands-on labs and investigations.

## Topics Covered

- SOC alert triage and investigation workflow
- HTTP status codes and response analysis
- Brute-force and authentication attacks
- Directory traversal and LFI
- RFI and SSRF identification
- Open redirection
- IDOR
- XXE
- Phishing investigation
- Process and network correlation
- C2 investigation
- IOC and artifact identification
- Successful vs. attempted attack determination
- Tier 2 escalation and containment decisions
- Analyst note documentation
- SIEM/EDR-first investigation methodology
- Dynamic malware analysis
- Windows Registry hive shorthand and persistence paths

## Investigation Philosophy

Start with the evidence already available in the SIEM and EDR.

**SIEM / EDR → Correlate Evidence → Deeper Analysis → Sandbox if Needed**

Sandboxing, packet analysis, and static malware analysis are useful when existing telemetry is insufficient, but they should not replace evidence already available in the SIEM.

---

# Field Guide — Part 2

> **Continuation Notice:** This section is Part 2 of the SOC/SIEM Investigation Field Guide and continues the material contained in `SOC_SIEM_Investigation_Field_Guide.docx`. It adds new hands-on investigation techniques, lessons learned, and reference material from authorized cybersecurity labs and training.

## Dynamic Malware Analysis

Dynamic malware analysis involves executing a suspicious file inside an isolated lab environment and observing its runtime behavior. The objective is to determine what the sample actually does, including process activity, file creation, Registry modification, persistence, and network communication.

**Investigation chain:**

`Execute → Processes → Files → Registry → Network → Persistence → C2 → Indicators`

### Dynamic Analysis Tool Reference

| Tool | Primary Use |
| --- | --- |
| Procmon | Runtime process, file system, Registry, and related activity |
| Process Hacker | Processes, parent/child relationships, handles, DLLs, and network connections |
| Regshot | Before-and-after Registry comparison |
| Wireshark | DNS, TCP/UDP, IP addresses, ports, and packet analysis |
| Fiddler | HTTP/HTTPS application traffic inspection |
| HashMyFiles | Generate and compare file hashes |

### Procmon — Detecting Dropped Files

Recommended capture routine:

`Clear old events → Start Capture → Execute Sample → Stop Capture → Filter`

Filtering after capture does not erase the captured evidence. Avoid over-filtering by the original sample name because malware may be renamed or a child process may perform additional activity.

Useful filters and operations include:

- `Process Name is <sample.exe>`
- `Path contains AppData`
- `CreateFile`
- `WriteFile`

**File-drop investigation pattern:**

`Malware process → AppData path → CreateFile / WriteFile → dropped executable`

Procmon can show file activity, but it does not calculate the file's cryptographic hash. Use a hashing tool when the investigation requires MD5, SHA-1, or SHA-256.

### Wireshark — Malware Network Activity

Start by identifying unusual DNS queries and correlate them with subsequent network connections.

**Network investigation pattern:**

`DNS query → Domain → Resolved IP → TCP connection → Destination port → Application traffic`

Useful display filters include:

- `dns`
- `http`
- `ip.addr == <suspicious-IP>`

When reading a TCP connection such as:

`50145 → 587`

`50145` is the temporary client/source port and `587` is the destination/service port.

A TCP `[SYN]` indicates the beginning of a connection attempt. Use **Follow TCP Stream** when necessary to inspect the complete conversation. Port `587` commonly represents SMTP message submission.

### Regshot — Registry Comparison

Recommended workflow:

`1st Shot → Execute Sample → 2nd Shot → Compare`

Review the comparison for:

- Keys added
- Values added
- Values modified

For persistence investigations, search for the dropped executable name and common startup locations such as `CurrentVersion\Run` and `CurrentVersion\RunOnce`. Correlate the Registry value with the executable it references.

## Windows Registry Hive Shorthand

Different Windows tools may display the same Registry hive using different names. When reviewing Regshot, Procmon, Registry Editor, SIEM, or EDR evidence, translate the shorthand before comparing paths or answering a lab question.

| Shorthand | Full Registry Hive |
| --- | --- |
| `HKU` | `HKEY_USERS` |
| `HKCU` | `HKEY_CURRENT_USER` |
| `HKLM` | `HKEY_LOCAL_MACHINE` |
| `HKCR` | `HKEY_CLASSES_ROOT` |
| `HKCC` | `HKEY_CURRENT_CONFIG` |

### Important HKU / HKCU Relationship

A tool such as Regshot may show a user's key as:

`HKU\<USER-SID>\Software\Microsoft\Windows\CurrentVersion\Run`

When that SID belongs to the currently logged-in user, the corresponding friendly path is:

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

`HKU` itself means `HKEY_USERS`. Do not automatically translate every `HKU` path to `HKEY_CURRENT_USER`; confirm that the SID belongs to the current user.

### Persistence Correlation

A common user-level persistence location is:

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

The equivalent current-user SID form may appear as:

`HKU\<CURRENT-USER-SID>\Software\Microsoft\Windows\CurrentVersion\Run`

Programs referenced by values under this key can be launched when that user logs on. During malware analysis, correlate the Registry value data with the dropped executable path before concluding that it is the malware's persistence mechanism.

**Investigation chain:**

`Dropped executable → Registry Run value → executable path matches → persistence evidence`

### Dynamic Analysis Rule

Do not rely on one artifact. Correlate behavior across the available evidence.

**`Process → File → Registry → Network → Persistence → IOC`**

Preserve evidence before remediation or resetting the lab. Start with the evidence that directly answers the investigation question, then go deeper only when necessary.

## Purpose

This repository is part of my cybersecurity portfolio and demonstrates how I organize and apply SOC investigation concepts during authorized training and lab environments.

## Disclaimer

All examples and techniques documented here are based on authorized cybersecurity training, lab environments, and defensive security analysis.

## Ongoing Development

This field guide is a living document.

I will continue adding new investigation techniques, attack patterns, indicators, search methods, and lessons learned as I progress through additional SOC labs and hands-on cybersecurity investigations.

The goal is to continuously improve this guide based on practical experience rather than treat it as a finished reference.
