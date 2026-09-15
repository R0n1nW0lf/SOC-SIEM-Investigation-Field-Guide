# REMnux Static Analysis — Quick Tool Selection

A quick-reference guide for selecting the right REMnux static-analysis tool based on the investigation question.

## Tool Selection

| Investigation Question | Tool | Primary Use |
| --- | --- | --- |
| What is this file really? | `file` | Identify the file type from its contents instead of trusting the extension |
| What metadata does it contain? | `ExifTool` | Inspect metadata, timestamps, software information, authorship, and file properties |
| What readable strings are present? | `strings` | Quickly extract readable text from a binary or other file |
| Are strings hidden or constructed? | `FLOSS` | Recover useful strings that may be encoded, decoded, or constructed by executable code |
| Could strings or data be XOR-obfuscated? | `XORSearch` | Search for strings and patterns hidden with XOR or related simple transformations |
| Does it match a known malware pattern? | `YARA` | Match files or memory against analyst-defined rules and known patterns |
| Does a PDF contain suspicious features? | `PDFiD` | Quickly triage PDF structures and identify potentially suspicious features |
| Need to inspect specific PDF objects? | `pdf-parser.py` | Examine PDF objects, streams, references, and suspicious content in greater detail |
| Need quick Windows PE triage? | `PEframe` | Surface suspicious characteristics and useful indicators from Windows PE files |
| What capabilities does the executable appear to have? | `capa` | Identify likely executable capabilities such as networking, process activity, file operations, or persistence-related behavior |
| Need deeper executable or binary inspection? | `rabin2` | Inspect binary headers, sections, imports, symbols, strings, libraries, and structure |
| Are files or data embedded inside something? | `Binwalk` | Identify embedded files, compressed data, filesystems, and other signatures inside a larger file or firmware image |

## Quick Memory Map

```text
What is this file really?             → file
What metadata does it contain?        → ExifTool
What readable strings are present?    → strings
Are strings hidden/constructed?       → FLOSS
Could data be XOR-obfuscated?          → XORSearch
Known malware/pattern match?           → YARA

Suspicious PDF?                       → PDFiD
Need to inspect PDF objects?          → pdf-parser.py

Suspicious Windows executable?        → PEframe
What can the executable do?           → capa
Need deeper binary structure?         → rabin2

Something embedded inside a file?     → Binwalk
```

## Tool Relationships

Some tools work especially well as a progression rather than as isolated commands.

### General File Triage

```text
file
 ↓
ExifTool
 ↓
strings
 ↓
Select deeper tool based on evidence
```

### String Investigation

```text
strings
 ↓
Useful plaintext found? → Investigate and correlate
 ↓ No
FLOSS / XORSearch
 ↓
Verify recovered values and determine what they belong to
```

### PDF Investigation

```text
PDFiD
 ↓
Identify suspicious PDF feature
 ↓
pdf-parser.py
 ↓
Inspect the relevant object or stream
 ↓
Correlate and verify
```

### Windows PE Investigation

```text
PEframe
 ↓
Quick PE triage
 ↓
capa
 ↓
Identify likely capabilities
 ↓
FLOSS / strings / rabin2 as needed
 ↓
Correlate with dynamic evidence when available
```

## Analyst Rule

> **Question → Correct Tool → Evidence → Correlate → Verify**

Do not run every tool simply because it is available. Start with the investigation question, select the tool that can provide the needed evidence, and pivot when the evidence points somewhere else.

A tool result is evidence, not automatically a conclusion. For example, a YARA match does not automatically prove that a file is malicious, and a capability identified by `capa` does not prove that the behavior actually executed. Correlate important findings with additional static, dynamic, endpoint, network, or sandbox evidence when possible.

## Purpose

This quick reference is designed for authorized malware-analysis labs and defensive security investigations. Commands and deeper examples can be added as they are encountered and verified through hands-on analysis.
