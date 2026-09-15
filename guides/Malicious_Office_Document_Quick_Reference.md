# Malicious Office Document — Quick Reference

Use this page when you already know **what you want to find** and need the fastest command instead of running every analysis tool.

> **Question → Correct Tool → Narrow Search → Verify**

---

## Before Using `oleid`, `olemeta`, or `olevba`

These commands are part of the **oletools** package. If they are not already installed on the Linux analysis machine, install oletools first.

### Installation method that worked in the Linux lab

```bash
sudo -H pip install -U 'oletools[full]'
```

This installs/updates **oletools with the full optional dependencies**. In some training/lab Linux environments this may work when the `pipx` method does not.

### Alternative isolated installation on modern Debian/Ubuntu/Kali-style systems

```bash
sudo apt update
sudo apt install pipx
pipx ensurepath
pipx install oletools
```

Then verify the tools are available:

```bash
oleid --help
olemeta --help
olevba --help
```

If `pipx` installation succeeds but the commands are not found immediately after `pipx ensurepath`, open a new terminal/session and try again. If the lab environment still does not expose the commands, use the working lab installation method above.

> **Already installed?** Skip this section and go directly to analysis.

---

## First: Know Which Stage You Are In

| Stage / Tool | What it answers | Example |
| --- | --- | --- |
| **`olemeta` — Metadata** | Who created/saved it? When? What application/template? | `olemeta filename` |
| **`oleid` — Triage / Detection** | Does it contain VBA/XLM macros, encryption, or suspicious Office features? | `oleid filename` |
| **`olevba` — VBA Investigation** | What does the macro contain? AutoExec? URLs? IOCs? commands? obfuscation? | `olevba filename` |
| **`grep` — Search extracted VBA** | I already extracted VBA. Find one specific clue quickly. | `grep -Ei 'https?://' filename.vba` |
| **`strings` — Search raw file strings** | I have not extracted VBA yet and want a quick raw-string hunt. | `strings filename | grep -Ei 'https?://'` |

### Simple memory rule

```text
WHO / WHEN?                 → olemeta
DOES IT HAVE A MACRO?       → oleid
WHAT DOES THE MACRO DO?     → olevba
FIND ONE THING IN THE VBA?  → grep
QUICK RAW FILE SEARCH?      → strings + grep
```

---

## What Do I Want to Find?

| Goal | Stage / Start With | Example |
| --- | --- | --- |
| Is this really the file type the extension claims? | **File verification — `file`** | `file filename` |
| What is the MD5? | **Hash — `md5sum`** | `md5sum filename` |
| What is the SHA256? | **Hash — `sha256sum`** | `sha256sum filename` |
| Who created/saved the document? | **Metadata — `olemeta`** | `olemeta filename` |
| When was it created or last saved? | **Metadata — `olemeta`** | `olemeta filename` |
| Does the document contain VBA macros? | **Triage — `oleid`** | `oleid filename` |
| Does it contain XLM macros? | **Triage — `oleid`** | `oleid filename` |
| Does it have external relationships? | **Triage — `oleid`** | `oleid filename` |
| What VBA code is inside? | **VBA analysis — `olevba`** | `olevba filename` |
| What causes the macro to auto-run? | **VBA analysis — `olevba`** | Look for `AutoExec`, `Document_Open`, `AutoOpen`, `Auto_Open`, `Workbook_Open` |
| What IOCs does olevba identify? | **VBA analysis — `olevba`** | Look at rows marked `IOC` |
| How many IOCs? | **VBA analysis — `olevba`** | Count rows whose Type is `IOC` |
| Is there an HTTP/HTTPS URL in the raw document? | **Raw search — `strings + grep`** | `strings filename | grep -Ei 'https?://'` |
| Is there a domain or URL in extracted VBA? | **After `olevba` extraction — `grep`** | `grep -Ei 'https?://|www\.' filename.vba` |
| Is PowerShell referenced? | **Extracted VBA — `grep`** | `grep -Ei 'powershell' filename.vba` |
| Is cmd.exe referenced? | **Extracted VBA — `grep`** | `grep -Ei 'cmd(\.exe)?' filename.vba` |
| Is an executable referenced? | **Extracted VBA — `grep`** | `grep -Ei '\.exe' filename.vba` |
| Is a DLL referenced? | **Extracted VBA — `grep`** | `grep -Ei '\.dll' filename.vba` |
| Is a JAR referenced? | **Extracted VBA — `grep`** | `grep -Ei '\.jar' filename.vba` |
| Does code use shell execution? | **Extracted VBA — `grep`** | `grep -Ei 'Shell|objShell\.Run|CreateObject' filename.vba` |
| Is there a Temp/AppData staging path? | **Extracted VBA — `grep`** | `grep -Ei 'temp|appdata|%temp%|%tmp%' filename.vba` |
| Is there obvious character/string obfuscation? | **Extracted VBA — `grep`** | `grep -Ei 'Chr\(|Asc\(' filename.vba` |
| Could a string be XOR-obfuscated? | **Obfuscation — `xorsearch`** | `xorsearch filename http` |
| Can the VBA be automatically revealed/deobfuscated? | **VBA analysis — `olevba`** | `olevba --deobf --reveal filename.vba` |
| Can macro behavior be emulated? | **VBA emulation — `vmonkey`** | `vmonkey filename` |
| Did execution modify the Registry? | **Dynamic — `Regshot`** | `1st Shot → Execute → 2nd Shot → Compare` |
| What processes/files/Registry operations occurred? | **Dynamic — `Procmon`** | Capture execution and filter relevant parent/children |
| What network traffic occurred? | **Dynamic — `Wireshark`** | Capture and filter DNS/IP/TCP/HTTP as needed |

---

## Fast HTTP / Network IOC Hunt

### Option A — Raw document (before VBA extraction)

```bash
strings filename | grep -Ei 'https?://|ftp://|www\.'
```

### Option B — Extract the VBA first with olevba

```bash
olevba filename > filename.vba
```

Then search the extracted VBA:

```bash
grep -Ei 'https?://|ftp://|www\.' filename.vba
```

Broader network-related hunt:

```bash
grep -Ei 'http|https|ftp|DownloadFile|WebClient|User-Agent' filename.vba
```

If nothing appears plainly, do **not** conclude there is no URL. It may be fragmented or obfuscated. Move to deobfuscation, variable tracing, XORSearch, or ViperMonkey.

---

## Fast Command / Execution Hunt

**Stage: extracted VBA (`olevba filename > filename.vba`)**

```bash
grep -Ei 'powershell|cmd(\.exe)?|cscript|wscript|Shell|objShell\.Run|CreateObject' filename.vba
```

Then inspect the surrounding code and determine **what exact command or object is being executed**.

---

## Fast Payload / File Hunt

**Stage: extracted VBA**

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

**Stage: extracted VBA**

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

Use **olevba** when you need:

- VBA source
- AutoExec triggers
- Suspicious keywords
- URLs/domains/IPs
- Executable names
- IOC count
- Obfuscation clues

Save the output so `grep` can search it repeatedly:

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
Need file type?               → file
Need hash?                    → md5sum / sha256sum
Need author/timestamps?       → olemeta   [METADATA]
Need to know if macros exist? → oleid     [TRIAGE]
Need actual VBA / IOCs?       → olevba    [VBA ANALYSIS]
Need a specific VBA string?   → grep      [AFTER VBA EXTRACTION]
Need raw printable strings?   → strings   [RAW FILE]
Need XOR-obfuscated clue?      → xorsearch [OBFUSCATION]
Need macro emulation?         → vmonkey   [EMULATION]
Need Registry changes?        → Regshot   [DYNAMIC]
Need runtime behavior?        → Procmon   [DYNAMIC]
Need network evidence?        → Wireshark [DYNAMIC]
```

## Time-Saving Rule

**Do not run every tool just because it exists. Start with the investigation question.**

`What am I looking for? → Identify the stage → Pick the tool that exposes that evidence → Narrow the output → Inspect context → Correlate → Verify`

If that tool reaches a dead end, pivot to the next evidence source instead of guessing.