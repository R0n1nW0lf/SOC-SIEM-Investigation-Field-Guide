# Malicious Office Document — Quick Reference

Use this page when you already know **what you want to find** and need the fastest command instead of running every analysis tool.

> **Question → Correct Tool → Narrow Search → Verify**

---

## What Do I Want to Find?

| Goal | Start With | Example |
| --- | --- | --- |
| Is this really the file type the extension claims? | `file` | `file filename` |
| What is the MD5? | `md5sum` | `md5sum filename` |
| What is the SHA256? | `sha256sum` | `sha256sum filename` |
| Who created/saved the document? | `olemeta` | `olemeta filename` |
| When was it created or last saved? | `olemeta` | `olemeta filename` |
| Does the document contain VBA macros? | `oleid` | `oleid filename` |
| Does it contain XLM macros? | `oleid` | `oleid filename` |
| Does it have external relationships? | `oleid` | `oleid filename` |
| What VBA code is inside? | `olevba` | `olevba filename` |
| What causes the macro to auto-run? | `olevba` | Look for `AutoExec`, `Document_Open`, `AutoOpen`, `Auto_Open`, `Workbook_Open` |
| What IOCs does olevba identify? | `olevba` | Look at rows marked `IOC` |
| How many IOCs? | `olevba` | Count rows whose Type is `IOC` |
| Is there an HTTP/HTTPS URL? | `strings + grep` | `strings filename \| grep -Ei 'https?://'` |
| Is there a domain or URL in extracted VBA? | `grep` | `grep -Ei 'https?://|www\.' filename.vba` |
| Is PowerShell referenced? | `grep` | `grep -Ei 'powershell' filename.vba` |
| Is cmd.exe referenced? | `grep` | `grep -Ei 'cmd(\.exe)?' filename.vba` |
| Is an executable referenced? | `grep` | `grep -Ei '\.exe' filename.vba` |
| Is a DLL referenced? | `grep` | `grep -Ei '\.dll' filename.vba` |
| Is a JAR referenced? | `grep` | `grep -Ei '\.jar' filename.vba` |
| Does code use shell execution? | `grep` | `grep -Ei 'Shell|objShell\.Run|CreateObject' filename.vba` |
| Is there a Temp/AppData staging path? | `grep` | `grep -Ei 'temp|appdata|%temp%|%tmp%' filename.vba` |
| Is there obvious character/string obfuscation? | `grep` | `grep -Ei 'Chr\(|Asc\(' filename.vba` |
| Could a string be XOR-obfuscated? | `xorsearch` | `xorsearch filename http` |
| Can the VBA be automatically revealed/deobfuscated? | `olevba` | `olevba --deobf --reveal filename.vba` |
| Can macro behavior be emulated? | `vmonkey` | `vmonkey filename` |
| Did execution modify the Registry? | `Regshot` | `1st Shot → Execute → 2nd Shot → Compare` |
| What processes/files/Registry operations occurred? | `Procmon` | Capture execution and filter relevant parent/children |
| What network traffic occurred? | `Wireshark` | Capture and filter DNS/IP/TCP/HTTP as needed |

---

## Fast HTTP / Network IOC Hunt

### Raw document

```bash
strings filename | grep -Ei 'https?://|ftp://|www\.'
```

### Extracted VBA

```bash
grep -Ei 'https?://|ftp://|www\.' filename.vba
```

### Broader network-related hunt

```bash
grep -Ei 'http|https|ftp|DownloadFile|WebClient|User-Agent' filename.vba
```

If nothing appears plainly, do **not** conclude there is no URL. It may be fragmented or obfuscated. Move to deobfuscation, variable tracing, XORSearch, or ViperMonkey.

---

## Fast Command / Execution Hunt

```bash
grep -Ei 'powershell|cmd(\.exe)?|cscript|wscript|Shell|objShell\.Run|CreateObject' filename.vba
```

Then inspect the surrounding code and determine **what exact command or object is being executed**.

---

## Fast Payload / File Hunt

```bash
grep -Ei '\.exe|\.dll|\.jar|\.ps1|\.bat|\.vbs' filename.vba
```

For staging locations:

```bash
grep -Ei 'temp|appdata|%temp%|%tmp%' filename.vba
```

Trace the filename/path into operations such as `Open`, `Write`, `Shell`, `.Run`, or `DownloadFile`.

---

## Fast Obfuscation Hunt

```bash
grep -Ei 'Chr\(|Asc\(' filename.vba
```

If code is fragmented:

`Find variable → Find definition → Decode/resolve value → Verify → Replace in WORKING COPY → Join fragments → Read complete command/URL/path`

Example:

```text
"http://1.1.1" + variable + ".exe"
```

If `variable = ".44/upd/install"`, reconstruct the working copy as:

```text
http://1.1.1.44/upd/install.exe
```

Never rewrite the original evidence.

---

## Fast olevba Workflow

```bash
olevba filename
```

Use it when you need:

- VBA source
- AutoExec triggers
- Suspicious keywords
- URLs/domains/IPs
- Executable names
- IOC count
- Obfuscation clues

Save the output:

```bash
olevba filename > filename.vba
```

Reveal/deobfuscate:

```bash
olevba --deobf --reveal filename.vba > filename_deobf.vba
```

---

## Fast Tool Decision

```text
Need file type?              → file
Need hash?                   → md5sum / sha256sum
Need author/timestamps?      → olemeta
Need to know if macros exist?→ oleid
Need actual VBA / IOCs?      → olevba
Need a specific string?      → grep
Need raw printable strings?  → strings
Need XOR-obfuscated clue?     → xorsearch
Need macro emulation?        → vmonkey
Need Registry changes?       → Regshot
Need runtime behavior?       → Procmon
Need network evidence?       → Wireshark
```

## Time-Saving Rule

**Do not run every tool just because it exists. Start with the investigation question.**

`What am I looking for? → Pick the tool that exposes that evidence → Narrow the output → Inspect context → Correlate → Verify`

If that tool reaches a dead end, pivot to the next evidence source instead of guessing.