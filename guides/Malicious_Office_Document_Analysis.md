# Malicious Office Document Analysis Guide

A practical workflow for analyzing suspicious Microsoft Office documents in authorized malware-analysis labs. The goal is to identify document capabilities, extract and understand macros, reconstruct obfuscated content, collect IOCs, and verify behavior without making assumptions.

## Core Investigation Workflow

`File → Hash → Type → Metadata → Macro Detection → Macro Extraction → Deobfuscation → IOC Hunt → Behavior Analysis → Sandbox → Correlate → Verify → Document`

The guiding rule is simple:

> **Do not assume what the document does. Identify the clue, collect the evidence, reconstruct the behavior, and verify it.**

---

## 1. Hash the File First

Generate hashes before deeper analysis so the sample can be identified consistently and checked against reputation sources.

```bash
md5sum filename
sha256sum filename
```

Recommended workflow:

`File → MD5 / SHA256 → Reputation Lookup → Review Existing Evidence → Correlate → Verify`

When possible, search the hash first instead of uploading a suspicious file to a public service.

A reputation result is evidence, not automatic proof of what happened on the local system.

---

## 2. Verify the Actual File Type

Do not trust the extension alone.

```bash
file filename
```

A file named `.doc`, `.xls`, or another Office extension may internally use a different format. Verify the actual structure before choosing analysis tools.

Modern Office macro-enabled extensions include:

| Extension | Type |
| --- | --- |
| `.docm` | Word macro-enabled document |
| `.dotm` | Word macro-enabled template |
| `.xlsm` | Excel macro-enabled workbook |
| `.pptm` | PowerPoint macro-enabled presentation |

The extension indicates capability, not proof that a macro is present or malicious.

---

## 3. Inspect Metadata

### ExifTool

```bash
exiftool filename
```

Useful for general file metadata and format information.

### olemeta

```bash
olemeta filename
```

Useful fields may include:

- Author
- Last Saved By
- Creation time
- Last saved time
- Application
- Template
- Revision
- Codepage

Metadata provides context. It should be correlated with other evidence rather than treated as proof of malicious behavior.

---

## 4. Identify Office Document Features with oleid

```bash
oleid filename
```

Use `oleid` as quick triage for features such as:

- Encryption
- VBA macros
- XLM macros
- External relationships

Example investigation pattern:

`oleid → VBA Macros detected → move to olevba`

A `HIGH` or suspicious result tells the analyst where to investigate next. It is not by itself proof that the macro is malicious.

---

## 5. Extract and Analyze VBA with olevba

```bash
olevba filename
```

`olevba` can extract VBA source and summarize important indicators.

### Important AutoExec Keywords

Examples include:

- `Document_Open`
- `AutoOpen`
- `Auto_Open`
- `Workbook_Open`

These can cause macro activity to begin automatically when the corresponding document or workbook is opened.

### Suspicious Keywords

Examples that may deserve investigation include:

- `Shell`
- `CreateObject`
- `GetObject`
- `Open`
- `Write`
- `Kill`
- `Environ`
- `User-Agent`
- `Chr`
- `PowerShell`
- `objShell.Run`

A suspicious keyword is a lead, not a conclusion. Inspect the surrounding VBA to determine what the code actually does.

### IOC Table

`olevba` may identify artifacts such as:

- URLs
- Domains
- IP addresses
- Executable filenames
- Other suspicious strings

If a lab asks **how many IOCs are present according to olevba**, count the rows whose type is `IOC`. Do not count only downloaded files or URLs.

**IOC workflow:**

`IOC table → select artifact → Find artifact in VBA → inspect surrounding code → determine context → verify`

---

## 6. Strings and Fast Keyword Hunting

```bash
strings -n 5 filename
```

`-n 5` means display printable strings with a minimum length of five characters. It does **not** mean display five lines.

Filter output with `grep`:

```bash
strings filename | grep -i "powershell"
strings filename | grep -Ei 'http|ftp|powershell'
```

Useful concepts:

- `grep -i` = case-insensitive search
- `grep -E` = extended regular expressions
- `| grep` = quickly search another command's output

`grep` normally finds the pattern anywhere within a line. Quotes protect the search pattern from shell interpretation; they do not create partial matching.

**Workflow:**

`Strings → Reduce Noise → Find Clue → Inspect Context → Verify`

---

## 7. Search for XOR-Obfuscated Content

```bash
xorsearch filename
```

Or search for a specific pattern:

```bash
xorsearch filename http
xorsearch filename powershell
xorsearch filename .exe
```

Useful patterns can include:

- `http`
- `https`
- `ftp`
- `.exe`
- `powershell`
- `cmd`
- `dll`

Finding a decoded pattern gives the analyst another clue to investigate. Determine how it is used before drawing a conclusion.

---

## 8. Manual VBA Deobfuscation

Obfuscated VBA often breaks meaningful strings into fragments so obvious keywords do not appear plainly in the source.

Example:

```text
Chr(Asc("C")) + "reate" + "O" + "bject"
```

Reconstruct the pieces:

```text
C + reate + O + bject
```

Result:

```text
CreateObject
```

Another example:

```text
"4" & "44." & Chr(101) & "xe"
```

`Chr(101)` resolves to `e`, producing:

```text
444.exe
```

### Analyst Mental Model

`Pieces + Pieces → Actual Value`

Search for clues such as:

- `Chr`
- `Asc`
- Heavy string concatenation
- Random-looking variable names
- Partial URLs
- Partial paths
- Partial command names

`Chr()` and `Asc()` are normal VBA functionality. Their presence alone is not malicious. Context matters.

---

## 9. Resolve Variables and Rewrite a Working Copy

When a variable or encoded fragment hides the meaning of the code, use **Find** to locate where it is defined.

Example concept:

```text
randomVariable = ".44/upd/install"
```

Elsewhere the macro may build:

```text
"http://1.1.1" + randomVariable + ".exe"
```

Resolve the variable and manually reconstruct the complete value in a working copy:

```text
http://1.1.1.44/upd/install.exe
```

This makes the macro easier to follow without repeatedly performing the reconstruction mentally.

### Find and Replace Workflow

`Find variable → Locate definition → Resolve/decode value → Verify value → Find & Replace in working copy → Join fragments → Reconstruct readable code → Continue analysis`

Only perform manual rewriting or Find & Replace on a **working/deobfuscated copy**. Preserve the original evidence unchanged so every reconstructed value can be verified against it.

This technique also applies when an encoded or meaningless-looking value is decoded into readable text:

`Encoded/obfuscated value → Decode → Verify → Replace in working copy → Reconstruct behavior`

---

## 10. Save and Deobfuscate VBA

A useful workflow demonstrated during training is:

```bash
olevba filename > filename.vba
olevba --deobf --reveal filename.vba > filename_deobf.vba
```

The `>` operator redirects command output into a file. It does not itself decode anything.

The first command saves the VBA analysis output. The second asks `olevba` to reveal/deobfuscate content and saves the result to another working file.

Review revealed strings for items such as:

- `powershell.exe`
- `objShell.Run`
- `cscript.exe`
- URLs
- IP addresses
- `.exe` filenames
- File-system paths

Compare reconstructed output against the original expression whenever possible.

**Workflow:**

`Deobfuscate → Review Revealed Strings → Compare with Original → Reconstruct Behavior → Verify`

Tool options may vary by installed version. Check the local version when needed:

```bash
olevba --help
```

---

## 11. objShell.Run and Command Execution

A construct such as:

```text
objShell.Run
```

is an important execution clue because the shell object may launch another program or command.

Do not stop at the `.Run` call.

**Investigation workflow:**

`Find objShell.Run → Inspect exact argument → Resolve variables/fragments → Deobfuscate if necessary → Determine exact command → Verify`

`objShell.Run` itself is not automatically malicious. What it executes determines its significance.

---

## 12. Temp and Staging Paths

Malicious code may write, execute, read, stage, or remove files from temporary locations.

Useful Windows locations include:

```text
C:\Users\<user>\AppData\Local\Temp\
%TEMP%
%TMP%
C:\Windows\Temp\
```

Search extracted VBA when useful:

```bash
grep -Ei 'temp|appdata|%temp%|%tmp%' filename.vba
```

Then trace the associated operation.

**Workflow:**

`Temp path → Identify filename → Trace Open/Write/Read/Shell/Run → Determine behavior → Verify`

---

## 13. Analyze Macro Behavior with ViperMonkey

```bash
vmonkey filename
```

ViperMonkey can emulate VBA behavior and help reveal actions hidden by obfuscation.

Recommended relationship between the tools:

`oleid → detect macro → olevba → inspect/extract VBA → vmonkey → emulate/analyze behavior → compare with source → verify`

ViperMonkey complements manual analysis. It does not replace analyst verification.

---

## 14. Static vs. Dynamic Analysis

Keep static and dynamic analysis environments separated by purpose.

### REMnux Malware Analysis VM

Use primarily for static analysis:

- File metadata
- Strings
- XORSearch
- `oleid`
- `olemeta`
- `olevba`
- ViperMonkey
- IOC extraction
- Deobfuscation

### Windows Malware Analysis VM

Use for controlled dynamic execution when necessary:

- Procmon
- Process Hacker
- Wireshark
- Regshot
- Fiddler
- Runtime process/file/Registry/network behavior

### Kali VM

Keep primarily for penetration-testing and authorized offensive-security labs rather than mixing malware-analysis environments unnecessarily.

---

## 15. Sandbox Analysis

When static analysis is insufficient, execute the sample only in an isolated and authorized malware-analysis environment or use an authorized sandbox.

Correlate sandbox findings across:

- Process tree
- Child processes
- Dropped files
- File-system changes
- Network connections
- DNS requests
- Registry activity
- Persistence
- IOCs

A sandbox summary is another evidence source, not a substitute for analyst verification.

**Workflow:**

`Execute in isolated environment → Observe behavior → Collect artifacts → Correlate process/file/network/Registry evidence → Verify → Document`

---

## 16. Add Regshot to Dynamic Document Analysis

Even when a lesson or sandbox does not specifically require Registry analysis, a before-and-after Registry comparison can reveal additional evidence.

Recommended workflow:

`Regshot 1st Shot → Execute document/VBA → Allow behavior to occur → Regshot 2nd Shot → Compare`

Review for:

- Added Registry keys
- Added values
- Modified values
- `Run` / `RunOnce` persistence
- Configuration changes
- References to dropped payloads
- Other Registry artifacts associated with execution

Do not assume every malicious document establishes Registry persistence. Some do; some do not. The malware's behavior depends on its purpose and implementation.

The purpose of checking is to avoid leaving an important evidence source unexplored.

### Negative Findings Matter

If the comparison shows no meaningful Registry changes, document that result instead of leaving the Registry section blank.

Example analyst note:

> **Registry Analysis:** A before-and-after Registry comparison was performed during execution. No significant Registry changes or Registry-based persistence mechanisms were observed.

A negative result is still useful evidence because it tells another analyst that the Registry was checked.

---

## 17. Reporting Checklist

A strong malicious-document report should document both observed behavior and important checks that produced no significant findings.

Review and record, when applicable:

- File name and verified type
- MD5 / SHA256
- Metadata
- Macro presence
- AutoExec trigger
- Extracted VBA
- Obfuscation/deobfuscation findings
- Reconstructed URLs, paths, and commands
- IOCs
- Process behavior
- Dropped files
- Network behavior
- Registry changes
- Persistence findings
- Sandbox findings
- Negative findings
- Evidence used to support each conclusion

**Reporting mindset:**

`What happened? → When did it happen? → What was the result? → How do I prove each one?`

Then:

`Collect → Correlate → Verify → Document`

---

## Quick Reference

```text
HASH
md5sum filename
sha256sum filename

TYPE
file filename

METADATA
exiftool filename
olemeta filename

OFFICE TRIAGE
oleid filename

VBA
olevba filename

STRINGS
strings -n 5 filename
strings filename | grep -Ei 'http|ftp|powershell'

XOR
xorsearch filename
xorsearch filename http

SAVE / DEOBFUSCATE VBA
olevba filename > filename.vba
olevba --deobf --reveal filename.vba > filename_deobf.vba

VBA EMULATION
vmonkey filename

SEARCH WORKING VBA
grep -Ei 'http|https|powershell|\.exe|objShell\.Run' filename.vba
grep -Ei 'temp|appdata|%temp%|%tmp%' filename.vba
```

## Final Rule

**Do not rely on one artifact or one tool.**

`Static evidence → Deobfuscation → Manual reconstruction → IOC correlation → Dynamic evidence → Registry/network/process verification → Report`

If a tool produces a suspicious result, treat it as a lead. Trace it back to the source, determine what the code actually does, correlate it with other evidence, and then make the analyst decision.

---

All techniques in this guide are intended for authorized cybersecurity training, defensive investigation, and isolated malware-analysis environments.