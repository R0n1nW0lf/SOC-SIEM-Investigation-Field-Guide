# Malicious VBA — Hex Deobfuscation and Reconstruction

Use this guide when a suspicious VBA macro contains encoded or fragmented strings that must be decoded before the behavior becomes readable.

> **Identify encoding → Decode → Reconstruct → Understand → Correlate → Verify**

---

## Why This Matters

Obfuscated VBA often hides useful evidence such as URLs, payload names, HTTP objects, User-Agent strings, file-writing objects, shell objects, and WMI paths inside encoded strings.

The goal is not simply to decode every strange-looking word. First determine whether the value is actually encoded data or only a randomized variable/function name.

For example, a name such as:

```text
vxedylctlyqvkl
```

may simply be an obfuscated identifier. Trying ROT/Caesar against it can waste time because there may be nothing to decode.

A value such as:

```text
68747470733a2f2f74696e
```

is a much stronger Hex candidate because it contains valid hexadecimal characters and an even number of characters.

---

## Recognizing a VBA Hex Decoder

A VBA function using logic similar to this is a strong indicator that strings are being decoded from Hex:

```vb
For i = 1 To Len(value) Step 2
    result = result & Chr$(Val("&H" & Mid$(value, i, 2)))
Next i
```

Important clues:

- `Step 2` processes two characters at a time.
- `&H` tells VBA to interpret the pair as hexadecimal.
- `Chr$()` converts the resulting byte value into a character.

When this pattern is present, test the supplied string with **CyberChef → From Hex**.

---

## Recommended Workflow

```text
Open / extract VBA safely
        ↓
Use olevba to improve readability
        ↓
Identify suspicious encoded strings
        ↓
Inspect the decoder function
        ↓
Determine encoding type
        ↓
Decode important strings in CyberChef
        ↓
Verify automated decoding when available
        ↓
Replace values in a WORKING COPY only
        ↓
Join fragmented strings in original order
        ↓
Reconstruct readable VBA behavior
        ↓
Trace variables and objects through execution
        ↓
Correlate → Verify → Conclusion
```

Never modify the original evidence. Keep manual Find & Replace and reconstruction work in a separate analysis copy.

---

## Using `olevba` for Faster Triage

Start by reading the VBA:

```bash
olevba filename
```

If `olevba` identifies or decodes obfuscated values, use that output to reduce repetitive manual work. Automated decoding is a useful lead, but important findings should still be verified.

A practical workflow is:

```text
olevba decoded output
        ↓
Identify important value
        ↓
CyberChef verification
        ↓
Find & Replace in working copy
        ↓
Reconstruct fragmented value
        ↓
Read behavior in context
```

This is faster than manually testing every string while still preserving analyst verification.

---

## Manual Hex Decode Example

Encoded fragment:

```text
68747470733a2f2f74696e
```

CyberChef recipe:

```text
From Hex
```

Decoded result:

```text
https://tin
```

A second fragment may decode separately. If VBA joins the calls with `&`, join the decoded results in the same order.

Example pattern:

```vb
decoder("HEX_PART_1") & decoder("HEX_PART_2")
```

Reconstruction:

```text
Decode PART 1
        +
Decode PART 2
        ↓
Join results exactly as VBA does
        ↓
Complete URL / filename / object / command
```

---

## Find & Replace Method

For repetitive deobfuscation, Find & Replace can make a working copy much easier to read.

Do **not** replace only the Hex characters while leaving the decoder function around the decoded text.

Incorrect reconstruction:

```vb
decoder("https://example")
```

The function would still attempt to interpret the readable text as encoded input.

Instead, replace the entire decoder call in the working copy with the decoded value:

```vb
"https://example"
```

Then join adjacent fragments and reread the surrounding VBA.

---

## What to Look For After Reconstruction

Once the strings become readable, trace how each value is used rather than treating the decoded string alone as the conclusion.

Common evidence includes:

| Decoded clue | What to investigate |
| --- | --- |
| URL/domain | Where is it supplied to the HTTP request? |
| `GET` / `POST` | Which object performs the request? |
| User-Agent | Which request header uses it? |
| `.exe`, `.dll`, `.jar` | Is it downloaded, written, or executed? |
| `ADODB.Stream` | Is response data being written to disk? |
| `WScript.Shell` | What command/file is being executed? |
| `winmgmts:` | Is WMI being used for process execution? |
| `Win32_Process` | What command line is passed to `.Create()`? |
| `%TEMP%` / `Environ("TEMP")` | Is the payload staged in a temporary directory? |
| `AutoOpen` / `Document_Open` | Does execution begin automatically when the document opens? |

---

## Reconstruct the Behavior, Not Just the Strings

A useful final reconstruction may look like:

```text
AutoOpen
   ↓
Macro routine
   ↓
Build remote URL
   ↓
Create HTTP object
   ↓
Send request
   ↓
Receive response body
   ↓
Create binary stream
   ↓
Write payload to disk
   ↓
Attempt execution
   ↓
WMI / shell execution path
```

This is more useful than a list of decoded strings because it explains the relationship between the artifacts.

---

## Demonstration — Manual Encode-to-Decode Analysis

A useful portfolio demonstration is to place the original obfuscated VBA beside a plain-text decoding worksheet:

```text
Original VBA / Hex fragments        Manual analysis
----------------------------        ------------------------------
Hex fragment                    →   CyberChef: From Hex
Split decoder calls             →   Decode each fragment
VBA `&` concatenation           →   Join decoded fragments
Randomized identifiers          →   Trace usage; do not assume encoding
Decoded object / URL / path     →   Find & Replace in working copy
Readable working copy           →   Reconstruct execution behavior
```

This demonstrates the analyst process rather than only presenting final answers:

**Raw evidence → encoding identification → manual decode → reconstruction → behavioral interpretation → verification.**

For portfolio use, clearly label the material as a **controlled malware-analysis training challenge** and avoid presenting active malware or executable payloads.

---

## Time-Saving Rule

Do not test every strange string against every CyberChef recipe until something looks readable.

```text
Inspect string
   ↓
Inspect surrounding code / decoder function
   ↓
Identify likely encoding
   ↓
Choose targeted CyberChef recipe
   ↓
Decode
   ↓
Verify
```

If the string does not have reliable encoding indicators, consider that it may simply be an obfuscated identifier and inspect how the code uses it before spending time decoding it.

---

## Analyst Rule

> **Decode the data, not every weird-looking name. Then reconstruct the relationships and verify the behavior.**
