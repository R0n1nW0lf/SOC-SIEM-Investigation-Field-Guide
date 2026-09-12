# Legacy Excel 4.0 / XLM Macro Triage Guide

This guide is a defensive quick-reference for analyzing suspicious legacy Excel `.xls` files and Excel 4.0 / XLM macro artifacts in authorized labs, SOC investigations, and malware-analysis environments.

The purpose is not to reproduce a specific training challenge or memorize one set of answers. The goal is to build a repeatable investigation method that adapts to whatever evidence the suspicious file exposes.

## Core Principle

**Do not force every suspicious file through the same fixed checklist.**

A workbook may expose metadata, defined names, hidden macro sheets, URLs, DLL references, command fragments, LOLBins, or other artifacts. The next step should depend on what the evidence reveals.

**File → Structure → Metadata → Macro Entry Point → Macro Logic → Command/Payload Artifacts → Correlate → Verify**

A discovered string is not proof that it executed. A URL is not proof of network access. A DLL name is not proof that the DLL was loaded or registered. Establish the execution chain whenever possible.

## 1. Confirm the File Type

Legacy Excel workbooks commonly use the OLE Compound Document format.

```bash
file suspicious.xls
```

A legacy workbook may appear as a `Composite Document File V2 Document`.

This matters because older `.xls` files are structurally different from modern `.xlsx` files and may store workbook data inside OLE streams such as `Book` or `Workbook`.

## 2. Inspect OLE Streams

If normal macro-analysis tooling fails, inspect the underlying OLE container instead of assuming the file is clean.

Typical streams may include:

- `Book`
- `Workbook`
- `SummaryInformation`
- `DocumentSummaryInformation`

Python with `olefile` can enumerate them:

```python
import olefile

ole = olefile.OleFileIO("suspicious.xls")
for stream in ole.listdir():
    print("/".join(stream))
```

## 3. Review Metadata

Metadata can provide useful context such as:

- Author
- Last saved by
- Creating application
- Creation time
- Last saved time

Treat metadata as evidence, not attribution by itself. A username in document metadata does not prove that person created or weaponized the file.

## 4. Identify Workbook Sheets

The BIFF `BOUNDSHEET` records describe workbook sheets and can reveal whether a sheet is a normal worksheet or an Excel 4.0 macro sheet.

Useful distinction:

- Normal worksheet
- Excel 4.0 / XLM macro sheet
- Chart
- Other legacy sheet types

When automated parsers fail, direct BIFF inspection can still identify the macro sheets and their workbook offsets.

## 5. Inspect Defined Names

Excel 4.0 macros can use defined names as execution entry points.

Important names to investigate include:

- `Auto_Open`
- `Auto_Close`
- `Auto_Activate`
- `Auto_Deactivate`

Finding `Auto_Open` is important because it can identify where XLM execution begins when the workbook is opened.

Do not stop at the name itself. Resolve where it points and follow the macro chain from that location.

## 6. Follow the Macro Entry Point

The useful question is not only:

> Does `Auto_Open` exist?

The useful questions are:

- What sheet and cell does it reference?
- What happens at that location?
- Does execution jump to another sheet or cell?
- What functions are invoked afterward?

This is where direct BIFF parsing or a working XLM-aware parser can be useful.

## 7. Search for XLM Functions and Suspicious Logic

Functions worth investigating include:

- `EXEC`
- `CALL`
- `REGISTER`
- `RUN`
- `FORMULA`
- `FORMULA.FILL`
- `SET.VALUE`
- `GET.WORKSPACE`
- `GET.CELL`
- `FOPEN`
- `FWRITE`
- `FCLOSE`
- `HALT`
- `RETURN`

For example, `EXEC` is especially important because it can be used to start an operating-system process.

However, finding the word `EXEC` does not automatically prove which command was launched. Follow the references and surrounding formula logic.

## 8. Look for Command Construction

XLM malware may build commands from multiple cells or fragments instead of storing one clean command line.

You may encounter evidence such as:

```text
svr32 -s
```

while another cell, formula, or fragment supplies the beginning of the executable name or the payload path.

Do not assume the final command from one fragment alone. Correlate:

**Macro function → command fragments → executable → arguments → payload**

Common LOLBins worth investigating include:

- `regsvr32.exe`
- `rundll32.exe`
- `powershell.exe`
- `cmd.exe`
- `mshta.exe`
- `certutil.exe`
- `bitsadmin.exe`
- `wmic.exe`
- `wscript.exe`
- `cscript.exe`
- `msiexec.exe`

## 9. Correlate Payload References

Legacy macro files may contain multiple DLL, executable, script, or temporary-file names.

Do not automatically select the first suspicious filename you find.

If two DLL names are present, determine which one is actually passed into the command or registration routine.

Useful investigation chain:

**Entry point → XLM function → command builder → LOLBin → argument → payload**

That chain is stronger evidence than simply finding two suspicious strings in the same workbook.

## 10. Extract URLs and Domains

Suspicious workbooks may contain download locations, C2 infrastructure, redirectors, or dead historical infrastructure.

Extract URLs and domain-like strings, but remember:

**Embedded URL ≠ confirmed network connection**

Correlate with:

- PCAP
- proxy logs
- firewall logs
- EDR
- DNS telemetry
- sandbox results
- historical threat intelligence

## 11. When Automated Tools Fail

Do not let one broken parser end the investigation.

Possible pivots:

- Direct OLE stream inspection
- Direct BIFF record parsing
- Printable string extraction
- Metadata inspection
- Another XLM parser
- CyberChef for encoding/obfuscation
- Sandbox analysis
- EDR/network correlation
- Historical reports

**Tool failure is not evidence that the artifact is benign.**

## Quick Python Helper

This repository includes:

```text
tools/xlm_triage.py
```

Usage:

```bash
python3 tools/xlm_triage.py suspicious.xls
```

Dependency:

```bash
pip install olefile
```

The helper can extract or identify, when present:

- SHA-256
- OLE streams
- Common document metadata
- `Book` / `Workbook` stream
- BOUNDSHEET information
- Excel 4.0 macro-sheet indicators
- Defined names such as `Auto_Open`
- Potential XLM functions
- Potential LOLBin names
- Partial command fragments
- DLL/executable/script references
- URLs
- Domain-like strings

Use `--strings` when the normal report is not enough:

```bash
python3 tools/xlm_triage.py suspicious.xls --strings
```

## Important Limitation

The helper is a triage tool, not an automatic malware verdict engine.

Its output changes based on what the suspicious file contains. Some files may expose a clean command line. Others may require manual BIFF analysis, formula tracing, decoding, dynamic analysis, or another evidence source.

The correct analyst workflow is:

**Tool extracts evidence → analyst follows the evidence → analyst correlates → analyst verifies**

If the result reveals a new artifact, pivot to that artifact. Do not force the investigation to match a predetermined answer.

## Analyst Reminder

**Presence does not equal execution.**

A file can contain:

- a malicious-looking URL that was never contacted
- a LOLBin name that was never launched
- multiple payload names where only one is used
- dead infrastructure that cannot be reproduced today
- decoy strings intended to confuse analysis

Document what you can prove, separate strong evidence from clues, and identify what remains unknown.

## Authorized Use

This guide and helper are intended for authorized cybersecurity labs, defensive malware analysis, SOC investigations, and threat-hunting environments.
