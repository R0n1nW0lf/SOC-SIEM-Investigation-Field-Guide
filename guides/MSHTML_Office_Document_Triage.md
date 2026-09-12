# MSHTML Office Document Triage

A quick-reference workflow for statically investigating suspicious Microsoft Office documents that may load remote content through MSHTML. This guide is based on defensive analysis techniques practiced in authorized lab environments.

> **Analyst rule:** A suspicious string is a clue, not proof. Extract the artifact, understand what it references, correlate the surrounding structure, and verify before assigning a CVE or declaring execution.

## Quick Investigation Flow

`Identify file type → Inspect package/structure → Open relationship data → Find suspicious keywords → Decode obfuscation if needed → Extract IOC → Correlate exploit pattern → Verify CVE`

## 1. Verify the Real File Type

Do not trust the filename extension by itself.

```bash
file suspicious.doc
xxd -l 8 suspicious.doc
```

An Office file named `.doc` can still contain an OOXML/ZIP package. A ZIP-based OOXML document normally begins with the `PK` signature (`50 4b 03 04`).

If it is ZIP/OOXML based:

```bash
unzip -l suspicious.doc
```

A useful location to inspect is:

```text
word/_rels/document.xml.rels
```

Display it without extracting the entire archive:

```bash
unzip -p suspicious.doc 'word/_rels/document.xml.rels'
```

## 2. Open the Whole Result First, Then Use Find

When possible, open or display the complete relationship/XML content first. Keep the surrounding context visible and use the viewer/editor's **Find** function to jump to known investigation keywords instead of manually reading every line or immediately reducing the evidence to grep output.

Useful keywords for this MSHTML pattern include:

```text
mhtml
x-usc
oleObject
TargetMode
External
http
https
```

This workflow preserves context:

`Open full artifact → Find keyword → inspect surrounding relationship → extract IOC → verify`

Command-line filtering is still useful when the file is large or when performing repeatable triage, but a narrow filter can hide useful surrounding evidence. Use the method that preserves the evidence needed for the investigation.

## 3. High-Value MSHTML Relationship Pattern

A relationship similar to the following deserves investigation:

```xml
<Relationship
  Type=".../oleObject"
  Target="mhtml:http://example.invalid/page.html!x-usc:http://example.invalid/page.html"
  TargetMode="External"/>
```

High-value clues include:

- `oleObject`
- `mhtml:`
- `!x-usc:`
- a remote URL or IP address
- `TargetMode="External"`

A useful mental shortcut is:

`External OLE object + MHTML handler + remote HTML → investigate possible MSHTML exploitation`

Do **not** treat `mhtml:` by itself as proof of malware or proof of a specific CVE. The relationship and surrounding behavior must be correlated.

## 4. Extract the IOC

The remote target may expose an IP address, domain, port, path, or other infrastructure indicator.

Example pattern:

```text
mhtml:http://example.invalid/path/page.html!x-usc:http://example.invalid/path/page.html
```

Separate the useful components:

```text
Protocol: HTTP
Domain: example.invalid
Path: /path/page.html
Relationship handler: mhtml
External-reference marker: x-usc
```

If the question asks for a domain, do not automatically include the port or path unless the requested format requires it.

## 5. Obfuscation Can Hide the Keywords

A plain Find/search for `mhtml` or `oleObject` may return nothing even though the relationship contains them. Attackers can represent characters as HTML/XML character references.

Examples:

```text
&#x6f;&#x6c;&#x65;&#x4f;&#x62;&#x6a;&#x65;&#x63;&#x74;
```

This is hexadecimal numeric character-reference encoding and decodes to:

```text
oleObject
```

Another form may look like:

```text
&#109;&#104;&#116;&#109;&#108;&#58;
```

This uses decimal numeric character references and begins decoding to:

```text
mhtml:
```

### Recognition Cheat Sheet

| Pattern | Likely Representation |
| --- | --- |
| `&#x41;` | HTML/XML numeric character reference using hexadecimal |
| `&#65;` | HTML/XML numeric character reference using decimal |
| `%41` or `%2F` | URL/percent encoding |
| `\x41` | Escaped hexadecimal byte |
| `\u0041` | Unicode escape |
| Long text using `A-Z a-z 0-9 + /` with possible `=` padding | Possible Base64 |
| Only hexadecimal pairs such as `68747470` | Possible hexadecimal data |

Pattern recognition gives a **likely** encoding. Verify it by decoding and checking whether the output becomes coherent and fits the surrounding evidence.

## 6. CyberChef Decoding Workflow

When obfuscation is encountered:

`Observe pattern → identify likely representation → choose matching CyberChef operation → decode → inspect output → check for another layer → correlate with original artifact`

For HTML/XML numeric character references, use an HTML-entity decoding operation. For other patterns, select the corresponding URL, Base64, hex, Unicode, or escape-decoding operation.

Do not randomly apply decoders until something readable appears. First identify the syntax and select the decoder that matches it.

Also expect layered obfuscation:

`Encoded value → decode layer 1 → recognize another encoding → decode layer 2 → final artifact`

Keep the original value and decoded result available so the transformation can be documented and verified.

## 7. How to Identify the CVE

Do not identify a CVE from the challenge title, a single keyword, or `mhtml:` alone.

Build a behavior fingerprint from the evidence first.

For the 2021 MSHTML Office exploitation pattern, important characteristics include:

```text
Microsoft Office document
        ↓
External OLE object relationship
        ↓
MHTML handler points to remote HTML
        ↓
MSHTML/browser rendering engine processes remote content
        ↓
Exploit chain may involve malicious ActiveX content and follow-on payload execution
```

Microsoft documented attacks exploiting **CVE-2021-40444** using specially crafted Office documents. In Microsoft's analysis, the exploit document used an **external oleObject relationship** with an **MHTML handler prefix** pointing to malicious remote HTML. The observed exploit chain then used malicious ActiveX content and follow-on payload execution.

Therefore, when evidence matches this fingerprint, **CVE-2021-40444 becomes a strong candidate**. Confirm the identification against an authoritative vulnerability source such as Microsoft MSRC/Microsoft Threat Intelligence, NVD, or CISA before recording the CVE.

### CVE Verification Rule

`Observed artifact → behavior fingerprint → candidate CVE → authoritative reference → confirmed attribution`

Do not reverse the workflow into:

`Known CVE name → force every artifact to fit it`

Similar techniques can appear in different vulnerabilities, campaigns, or benign document behavior.

## 8. When the Expected Keyword Is Missing

If `mhtml`, `x-usc`, or another expected string is not visible:

1. Confirm the actual file format rather than trusting the extension.
2. Inspect the correct relationship or embedded-object structure.
3. Look for numeric character references or another encoding/obfuscation layer.
4. Decode suspicious values and search the decoded output.
5. Inspect other relationships, embedded objects, URLs, scripts, or payload references.
6. Correlate with network, sandbox, EDR, or threat-intelligence evidence when static evidence is insufficient.

Absence of a plain-text keyword does not prove the behavior is absent.

## 9. Quick Reference

```text
Suspicious Office document
        ↓
file / magic bytes
        ↓
OOXML? Inspect ZIP structure
        ↓
word/_rels/document.xml.rels
        ↓
Open whole relationship file
        ↓
Find: oleObject / mhtml / x-usc / External
        ↓
Encoded or obfuscated?
        ↓
Identify representation → CyberChef → decode
        ↓
Extract domain / IP / URL / payload reference
        ↓
Correlate the complete behavior pattern
        ↓
Compare with authoritative CVE documentation
        ↓
Analyst verifies conclusion
```

## Analyst Takeaway

The fastest investigation is not always the one with the most commands. Once a useful pattern is known, use **Find** to jump to it while keeping the complete artifact visible. If the expected text is hidden, recognize the encoding or obfuscation, decode it deliberately, and continue following the evidence.

**Open → Find → Decode if needed → Correlate → Verify.**

## Safety and Scope

Perform suspicious-document analysis only in authorized environments. Prefer static analysis first. Do not open or execute an untrusted Office document on a production workstation merely to determine whether an exploit triggers.
