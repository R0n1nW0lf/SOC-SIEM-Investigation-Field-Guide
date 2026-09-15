# Malicious Office Document — Quick Reference

Use this page when you already know **what you want to find** and need the fastest command instead of running every analysis tool.

> **Question → Correct Tool → Narrow Search → Verify**

---

## Recommended Starting Point — Sandbox First, Then Static Analysis

When policy and the analysis environment allow it, start by checking the suspicious file or its hash in a malware-analysis sandbox such as **Hybrid Analysis**, **ANY.RUN**, or another trusted sandbox service.

If the file is sensitive, confidential, or belongs to a client/employer, **do not upload it to a public sandbox unless policy explicitly permits it**. Prefer searching the file hash first or use an approved private/internal sandbox.

Use the sandbox to get a firsthand behavioral overview:

- Process tree and parent/child relationships
- Full command lines and encoded command arguments
- DNS requests and contacted domains/IPs
- HTTP/HTTPS or other network activity
- Files created, downloaded, or dropped
- Registry changes or persistence behavior when available
- Suspicious child processes such as Office applications spawning PowerShell, cmd, wscript, or cscript

Then use **oletools and other static-analysis tools** to investigate the document itself and explain **why** that behavior occurred.

```text
File / Hash
    ↓
Sandbox behavioral overview
    ↓
Identify processes + commands + DNS + network + dropped files
    ↓
oleid / olemeta / olevba / strings / grep
    ↓
Trace behavior back into document code
    ↓
Correlate sandbox evidence with static evidence
    ↓
Verify → Conclusion
```

A sandbox result is evidence, not an automatic verdict. If sandbox and static results disagree, investigate the difference instead of choosing whichever result looks more suspicious.

---

## IOC Relationship Verification — Do Not Stop at the IOC

Finding an IP, domain, URL, hash, or filename does **not** automatically mean it is the artifact relevant to the question or incident. A report may contain several legitimate, malicious, or unrelated network endpoints at different stages of execution.

**Do not just find the IOC. Find what it belongs to.**

```text
Find IOC
   ↓
Identify associated process / file
   ↓
Determine behavior or purpose
   ↓
Correlate with incident timeline
   ↓
Verify against another evidence source when possible
   ↓
Conclusion
```

For an IP and port, prefer evidence that directly associates the endpoint with the relevant process:

```text
IP:PORT → Associated Process → Parent/Child Chain → Behavior → Timeline
```

Example investigation logic:

- A sandbox may show one IP as a download server and another IP as a connection made by the exploited process.
- Both IPs can be real evidence, but only one may answer the investigation question.
- A generic **Contacted Server** entry is weaker for process attribution than a **Contacted Host / Network Connection** entry that identifies the associated process.
- If VirusTotal relationships or one sandbox do not expose the relationship you need, treat that source as a dead end for that question and pivot to another sandbox or telemetry source.
- Do not change an IOC just because an answer was rejected. Return to the evidence and identify the missing relationship.

Useful pivot pattern:

```text
VirusTotal / reputation lookup
        ↓
Relationship available? ── YES → Correlate and verify
        │
        NO
        ↓
Hybrid Analysis / ANY.RUN / other approved sandbox
        ↓
Contacted Hosts / Process Tree / Network Activity
        ↓
Match IOC + Process + Behavior + Timeline
        ↓
Verify
```

---

## Before Using `oleid`, `olemeta`, or `olevba`

These commands are part of the **oletools** package. If they are not already installed on the Linux analysis machine, install oletools first.

### Installation method that worked in the Linux lab

```bash
sudo -H pip install -U 'oletools[full]'
```

This installs/updates **oletools with the full optional dependencies**. In some training/lab Linux environments this may work when the `pipx` method does not.

### Preferred isolated installation on modern Debian/Ubuntu/REMnux systems

Modern Python environments may block system-wide `pip install` with an externally-managed-environment warning. Do not force system Python when that happens. Use `pipx`:

```bash
sudo apt update
sudo apt install pipx
pipx ensurepath
pipx install oletools
```

If installation succeeds but `/home/<user>/.local/bin` is not active in the current PATH, close the terminal and open a new one after `pipx ensurepath`.

Then verify:

```bash
oleid --help
olemeta --help
olevba --help
```

> **Already installed?** Skip this section and go directly to analysis.

---

## oletools Suite — Pick the Tool for the Evidence

Installing `oletools` provides more than `oleid`, `olemeta`, and `olevba`. Do **not** run every utility automatically. Start with the investigation question and choose the tool that can expose the evidence you need.

| Tool | Use it for |
| --- | --- |
| **`olevba`** | Extract and analyze VBA/macros; AutoExec triggers, suspicious keywords, IOCs, encoded strings, and deobfuscation. |
| **`oleid`** | Quick Office/OLE triage; identify macros and suspicious document features. |
| **`olemeta`** | Document metadata such as author, creation/modification timestamps, and properties. |
| **`oleobj`** | Find and extract embedded OLE objects/files from Office or RTF documents. |
| **`olemap`** | Inspect the internal structure/layout of an OLE file for deeper analysis. |
| **`oledir`** | List the internal OLE directory, storage, and stream structure. |
| **`olebrowse`** | Interactively browse OLE streams and storage when manual inspection is needed. |
| **`olefile`** | Lower-level OLE file inspection/access for deeper structural work. |
| **`oletimes`** | Inspect timestamps associated with OLE streams/storage for timeline or forensic work. |
| **`rtfobj`** | Analyze RTF documents and locate/extract embedded objects; useful for suspicious or exploit-bearing RTF files. |
| **`msodde`** | Detect/extract DDE links and commands from Microsoft Office documents. |
| **`mraptor`** | Rapid VBA macro risk triage based on potentially malicious macro characteristics. |
| **`ftguess`** | Guess the actual file type when an extension may be misleading. |
| **`ezhexviewer`** | View raw file content in hexadecimal form for lower-level inspection. |
| **`pyxswf`** | Extract/decompress embedded SWF/Flash content; mainly useful for older malware/exploit samples. |

### Quick memory map

```text
What is this file really?       → ftguess
Quick Office triage             → oleid
Who / when metadata             → olemeta
What does the macro do?         → olevba
Embedded object/file?           → oleobj
Suspicious RTF object?          → rtfobj
DDE command/link?               → msodde
OLE timestamps/timeline?        → oletimes
Deep OLE structure?             → oledir / olemap / olebrowse / olefile
Quick macro-risk check?         → mraptor
Raw hex inspection?             → ezhexviewer
Legacy embedded Flash/SWF?      → pyxswf
```

**Rule:** `Question → Correct Tool → Evidence → Correlate → Verify`

---

## First: Know Which Stage You Are In

| Stage / Tool | What it answers | Example |
| --- | --- | --- |
| **Sandbox — Behavioral overview** | What processes, commands, DNS/network activity, and dropped files appeared during execution? | Hybrid Analysis / ANY.RUN / approved sandbox |
| **`olemeta` — Metadata** | Who created/saved it? When? What application/template? | `olemeta filename` |
| **`oleid` — Triage / Detection** | Does it contain VBA/XLM macros, encryption, or suspicious Office features? | `oleid filename` |
| **`olevba` — VBA Investigation** | What does the macro contain? AutoExec? URLs? IOCs? commands? obfuscation? | `olevba filename` |
| **`grep` — Search extracted VBA** | I already extracted VBA. Find one specific clue quickly. | `grep -Ei 'https?://' filename.vba` |
| **`strings` — Search raw file strings** | I have not extracted VBA yet and want a quick raw-string hunt. | `strings filename | grep -Ei 'https?://'` |

### Simple memory rule

```text
WHAT DID IT DO?              → sandbox / dynamic evidence
WHO / WHEN?                  → olemeta
DOES IT HAVE A MACRO?        → oleid
WHAT DOES THE MACRO DO?      → olevba
FIND ONE THING IN THE VBA?   → grep
QUICK RAW FILE SEARCH?       → strings + grep
```

---

## What Do I Want to Find?

| Goal | Stage / Start With | Example |
| --- | --- | --- |
| What happened when the document executed? | **Sandbox — behavioral overview** | Review process tree, command lines, network, dropped files |
| Which process made a connection? | **Sandbox — process/network correlation** | Match process tree/command line to network behavior |
| What DNS requests were actually sent? | **Sandbox / Wireshark — network evidence** | Review DNS activity; in Wireshark use `dns` or `dns.flags.response == 0` |
| What filename was downloaded or dropped? | **Sandbox + static correlation** | Check dropped/downloaded files, then trace filename into VBA/command line |
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

If nothing appears plainly, do **not** conclude there is no URL. It may be fragmented or obfuscated. Move to deobfuscation, variable tracing, XORSearch, ViperMonkey, or sandbox/network evidence.

---

## Fast Command / Execution Hunt

**Stage: extracted VBA (`olevba filename > filename.vba`)**

```bash
grep -Ei 'powershell|cmd(\.exe)?|cscript|wscript|Shell|objShell\.Run|CreateObject' filename.vba
```

Then inspect the surrounding code and determine **what exact command or object is being executed**.

If static searching only produces a generic suspicious-keyword result and does not reveal the actual command, pivot to the sandbox **process tree / command line** and correlate the command back to the document.

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

Trace the filename/path into operations such as `Open`, `Write`, `Shell`, `.Run`, or `DownloadFile`. If the filename is clearer in the sandbox report, use that artifact as a lead and trace it back into the static code.

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
Need behavioral overview?        → Sandbox (Hybrid Analysis / ANY.RUN / approved equivalent)
Need IOC relationship/context?   → Sandbox process/network correlation; pivot if reputation source is a dead end
Need process tree/command line?   → Sandbox / Procmon / Process monitoring
Need actual DNS requests?        → Sandbox / Wireshark
Need file type?                  → file / ftguess
Need hash?                       → md5sum / sha256sum
Need author/timestamps?          → olemeta   [METADATA]
Need to know if macros exist?    → oleid     [TRIAGE]
Need actual VBA / IOCs?          → olevba    [VBA ANALYSIS]
Need embedded OLE object?        → oleobj    [OBJECT EXTRACTION]
Need suspicious RTF object?      → rtfobj    [RTF ANALYSIS]
Need DDE command/link?           → msodde    [DDE ANALYSIS]
Need OLE stream timestamps?      → oletimes  [FORENSICS]
Need deeper OLE structure?       → oledir / olemap / olebrowse / olefile
Need quick macro-risk triage?    → mraptor
Need raw hex view?               → ezhexviewer
Need a specific VBA string?      → grep      [AFTER VBA EXTRACTION]
Need raw printable strings?      → strings   [RAW FILE]
Need XOR-obfuscated clue?        → xorsearch [OBFUSCATION]
Need macro emulation?            → vmonkey   [EMULATION]
Need Registry changes?           → Regshot   [DYNAMIC]
Need runtime behavior?           → Procmon   [DYNAMIC / WINDOWS]
Need network evidence?           → Wireshark [DYNAMIC]
```

## Time-Saving Rule

**Do not run every tool just because it exists. Start with the investigation question.**

`What am I looking for? → Identify the stage → Pick the tool that exposes that evidence → Narrow the output → Inspect context → Correlate → Verify`

If that tool reaches a dead end, pivot to the next evidence source instead of guessing.

A useful pattern from hands-on analysis is:

**Sandbox clue → static document evidence → dynamic/network correlation → verify.**