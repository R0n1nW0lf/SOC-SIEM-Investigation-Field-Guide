# File Hash & Reputation Triage

A quick-reference workflow for generating file hashes and using them to look for existing threat-intelligence reports without executing or uploading the file.

## Generate File Hashes

### MD5

```bash
md5sum filename
```

Example output:

```text
d7e6921bfd008f707ba52dee374ff3db  filename.doc
```

The 32-character hexadecimal value is the file's MD5 hash.

### SHA-256

```bash
sha256sum filename
```

The resulting 64-character hexadecimal value is the file's SHA-256 hash.

## Why Calculate More Than One Hash?

A hash acts as a fingerprint for the exact file contents. MD5 is still commonly encountered as an IOC and can be useful for reputation lookups, while SHA-256 is stronger and commonly used for modern file identification and threat intelligence.

Changing the file changes its hash, so always calculate the hash from the exact sample being investigated.

## Threat-Intelligence Lookup

After calculating the hash:

```text
Suspicious file → Calculate MD5 / SHA-256 → Copy hash → Search threat-intelligence service → Review existing report → Correlate with local evidence → Verify
```

VirusTotal supports searching existing file reports using MD5, SHA-1, or SHA-256 hashes. Other authorized malware-analysis or threat-intelligence services may provide similar hash-search capabilities.

Searching the hash first is useful because it can retrieve an existing report without requiring the analyst to upload or execute the suspicious file.

## What to Review in a Reputation Report

Look for evidence such as:

- Detection ratio / security-vendor results
- Malware family or classification names
- First-seen and last-analysis information
- File names associated with the hash
- File type and size
- Sandbox verdicts or behavioral information when available
- Related domains, IP addresses, URLs, dropped files, or other IOCs when available

## Analyst Rule

A reputation result is another evidence source, not the entire investigation.

Do not conclude that a file is malicious or harmless from one vendor result alone. Correlate the reputation report with the file's metadata, strings, document structure, macros, process behavior, network activity, EDR/SIEM telemetry, and other available evidence.

**Workflow:**

`Hash → Reputation → Context → Correlate → Verify`

## Operational Note

When investigating organizational or client files, check policy before uploading a sample to a third-party service. Searching an already calculated hash can provide existing intelligence without submitting the file itself.
