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
- Windows Registry hive shorthand and persistence paths

## Investigation Philosophy

Start with the evidence already available in the SIEM and EDR.

**SIEM / EDR → Correlate Evidence → Deeper Analysis → Sandbox if Needed**

Sandboxing, packet analysis, and static malware analysis are useful when existing telemetry is insufficient, but they should not replace evidence already available in the SIEM.

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

A tool such as Regshot may show a logged-in user's key as:

`HKU\<USER-SID>\Software\Microsoft\Windows\CurrentVersion\Run`

For that logged-in user, the equivalent friendly path is:

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

`HKU` itself means `HKEY_USERS`. Do not blindly replace every `HKU` path with `HKEY_CURRENT_USER`; the equivalence applies when the `HKU\<SID>` hive is the currently logged-in user's hive.

### Common Persistence Example

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

Programs referenced by values under this key can be launched when that user logs on. During malware analysis, correlate the Registry value data with the dropped executable path before concluding that it is the malware's persistence mechanism.

**Example investigation chain:**

`Dropped executable → Registry Run value → executable path matches → persistence established`

## Purpose

This repository is part of my cybersecurity portfolio and demonstrates how I organize and apply SOC investigation concepts during authorized training and lab environments.

## Disclaimer

All examples and techniques documented here are based on authorized cybersecurity training, lab environments, and defensive security analysis.

## Ongoing Development

This field guide is a living document.

I will continue adding new investigation techniques, attack patterns, indicators, search methods, and lessons learned as I progress through additional SOC labs and hands-on cybersecurity investigations.

The goal is to continuously improve this guide based on practical experience rather than treat it as a finished reference.
