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

## Investigation Philosophy

Start with the evidence already available in the SIEM and EDR.

**SIEM / EDR → Correlate Evidence → Deeper Analysis → Sandbox if Needed**

Sandboxing, packet analysis, and static malware analysis are useful when existing telemetry is insufficient, but they should not replace evidence already available in the SIEM.

## Purpose

This repository is part of my cybersecurity portfolio and demonstrates how I organize and apply SOC investigation concepts during authorized training and lab environments.

## Disclaimer

All examples and techniques documented here are based on authorized cybersecurity training, lab environments, and defensive security analysis.
