#!/usr/bin/env python3
"""
XLM / Legacy Excel Triage Helper

Defensive triage utility for suspicious legacy .xls / OLE workbooks.
It does not execute workbook content and does not decide whether a file is malicious.
It extracts evidence so an analyst can correlate findings manually.

Dependency:
    pip install olefile

Usage:
    python3 xlm_triage.py suspicious.xls
"""

import argparse
import hashlib
import os
import re
import struct
import sys
from urllib.parse import urlparse

try:
    import olefile
except ImportError:
    print("[!] Missing dependency: olefile")
    print("    Install with: pip install olefile")
    sys.exit(1)


BUILTIN_NAMES = {
    0x01: "Auto_Open",
    0x02: "Auto_Close",
    0x03: "Extract",
    0x04: "Database",
    0x05: "Criteria",
    0x06: "Print_Area",
    0x07: "Print_Titles",
    0x08: "Recorder",
    0x09: "Data_Form",
    0x0A: "Auto_Activate",
    0x0B: "Auto_Deactivate",
    0x0C: "Sheet_Title",
    0x0D: "_FilterDatabase",
}

SHEET_TYPES = {
    0x00: "Worksheet/Dialog",
    0x01: "Excel 4.0 Macro Sheet",
    0x02: "Chart",
    0x06: "VB Module",
}

XLM_KEYWORDS = [
    "EXEC", "CALL", "REGISTER", "RUN", "FORMULA", "FORMULA.FILL",
    "SET.VALUE", "GET.WORKSPACE", "GET.CELL", "HALT", "RETURN",
    "FOPEN", "FWRITE", "FCLOSE", "URLDOWNLOADTOFILE",
]

LOLBINS = [
    "regsvr32", "rundll32", "powershell", "cmd.exe", "mshta",
    "certutil", "bitsadmin", "wmic", "wscript", "cscript",
    "msiexec", "installutil", "regasm", "regsvcs",
]

INTERESTING_EXTENSIONS = (
    ".dll", ".exe", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta",
    ".scr", ".com", ".zip", ".rar", ".cab", ".tmp", ".dat",
)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def printable_strings(data, min_len=4):
    ascii_hits = [m.group().decode("latin1", errors="ignore")
                  for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]

    wide_hits = []
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for m in wide_re.finditer(data):
        try:
            wide_hits.append(m.group().decode("utf-16le", errors="ignore"))
        except Exception:
            pass

    # Preserve order while deduplicating.
    return list(dict.fromkeys(ascii_hits + wide_hits))


def parse_biff_records(data):
    pos = 0
    while pos + 4 <= len(data):
        rid, size = struct.unpack("<HH", data[pos:pos + 4])
        end = pos + 4 + size
        if end > len(data):
            break
        yield pos, rid, data[pos + 4:end]
        pos = end


def parse_boundsheets(data):
    results = []
    for pos, rid, rec in parse_biff_records(data):
        if rid != 0x0085 or len(rec) < 8:
            continue

        bof = struct.unpack("<I", rec[:4])[0]
        flags = struct.unpack("<H", rec[4:6])[0]
        sheet_type = flags & 0x00FF
        visibility = flags & 0x0003
        cch = rec[6]

        # BIFF8 names include an option byte before the text. Older BIFF can be ANSI.
        name = None
        if len(rec) >= 8:
            opts = rec[7]
            raw = rec[8:]
            try:
                if opts & 0x01:
                    name = raw[:cch * 2].decode("utf-16le", errors="replace")
                else:
                    name = raw[:cch].decode("latin1", errors="replace")
            except Exception:
                name = None

        if not name:
            raw = rec[7:7 + cch]
            name = raw.decode("latin1", errors="replace")

        results.append({
            "record_offset": pos,
            "bof_offset": bof,
            "name": name,
            "type": SHEET_TYPES.get(sheet_type, f"Unknown (0x{sheet_type:02x})"),
            "visibility": visibility,
        })
    return results


def parse_defined_names(data):
    results = []
    for pos, rid, rec in parse_biff_records(data):
        if rid != 0x0018 or len(rec) < 15:
            continue

        flags = struct.unpack("<H", rec[:2])[0]
        builtin = bool(flags & 0x0020)
        cch = rec[3] if len(rec) > 3 else 0
        entry = {"offset": pos, "builtin": builtin, "name": None}

        if builtin:
            # Common older BIFF layout: built-in name identifier is byte 14.
            if len(rec) > 14:
                name_id = rec[14]
                entry["name"] = BUILTIN_NAMES.get(name_id, f"Built-in 0x{name_id:02x}")
        else:
            # Best-effort extraction of readable user-defined name.
            candidates = re.findall(rb"[A-Za-z_][A-Za-z0-9_.]{2,}", rec)
            if candidates:
                entry["name"] = candidates[0].decode("latin1", errors="ignore")

        if entry["name"]:
            results.append(entry)
    return results


def classify_strings(strings):
    findings = {
        "xlm_functions": [],
        "lolbins": [],
        "urls": [],
        "domains": [],
        "file_refs": [],
        "command_fragments": [],
    }

    url_re = re.compile(r"https?://[^\s\"'<>]+", re.I)
    domain_re = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")

    for s in strings:
        low = s.lower()

        for keyword in XLM_KEYWORDS:
            if keyword.lower() in low:
                findings["xlm_functions"].append(keyword)

        for lolbin in LOLBINS:
            if lolbin in low:
                findings["lolbins"].append(lolbin)

        # Useful when obfuscation stores only a partial executable name.
        if "svr32" in low and "regsvr32" not in low:
            findings["command_fragments"].append(s)

        findings["urls"].extend(url_re.findall(s))

        for d in domain_re.findall(s):
            # Avoid treating ordinary DLL names as domains.
            if not d.lower().endswith(INTERESTING_EXTENSIONS):
                findings["domains"].append(d)

        # Extract path-like or command-like references ending in interesting extensions.
        for token in re.split(r"[\s\"',;()]+", s):
            clean = token.strip()
            if clean.lower().endswith(INTERESTING_EXTENSIONS):
                findings["file_refs"].append(clean)

    for key in findings:
        findings[key] = list(dict.fromkeys(findings[key]))
    return findings


def safe_meta_value(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def main():
    parser = argparse.ArgumentParser(
        description="Defensive triage helper for suspicious legacy Excel/OLE workbooks"
    )
    parser.add_argument("file", help="Path to suspicious .xls/OLE workbook")
    parser.add_argument("--strings", action="store_true",
                        help="Also print all extracted printable strings")
    args = parser.parse_args()

    path = args.file
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        return 2

    print("=== XLM / Legacy Excel Triage ===")
    print(f"File: {os.path.abspath(path)}")
    print(f"SHA256: {sha256_file(path)}")

    if not olefile.isOleFile(path):
        print("\n[!] File is not an OLE Compound Document.")
        print("    This helper is intended primarily for legacy .xls/OLE workbooks.")
        return 1

    ole = olefile.OleFileIO(path)

    print("\n[OLE Streams]")
    streams = ["/".join(x) for x in ole.listdir()]
    for stream in streams:
        print(f"  {stream}")

    print("\n[Metadata]")
    try:
        meta = ole.get_metadata()
        metadata = {
            "Author": safe_meta_value(getattr(meta, "author", None)),
            "Last Saved By": safe_meta_value(getattr(meta, "last_saved_by", None)),
            "Creating Application": safe_meta_value(getattr(meta, "creating_application", None)),
            "Create Time": safe_meta_value(getattr(meta, "create_time", None)),
            "Last Saved Time": safe_meta_value(getattr(meta, "last_saved_time", None)),
        }
        shown = False
        for key, value in metadata.items():
            if value and value != "None":
                print(f"  {key}: {value}")
                shown = True
        if not shown:
            print("  No common metadata fields recovered.")
    except Exception as e:
        print(f"  Metadata read failed: {e}")

    workbook_stream = None
    for candidate in ("Workbook", "Book"):
        if ole.exists(candidate):
            workbook_stream = candidate
            break

    if not workbook_stream:
        print("\n[!] No Workbook or Book stream found.")
        print("    Continue with the other OLE streams and extracted strings manually.")
        return 0

    data = ole.openstream(workbook_stream).read()
    print(f"\n[Workbook Stream]\n  {workbook_stream} ({len(data)} bytes)")

    sheets = parse_boundsheets(data)
    if sheets:
        print("\n[Sheets / BOUNDSHEET]")
        for item in sheets:
            vis = "visible" if item["visibility"] == 0 else f"visibility={item['visibility']}"
            print(f"  {item['name']}: {item['type']} | {vis} | BOF=0x{item['bof_offset']:x}")

    names = parse_defined_names(data)
    if names:
        print("\n[Defined Names]")
        for item in names:
            kind = "built-in" if item["builtin"] else "user-defined"
            print(f"  {item['name']} ({kind}) @ 0x{item['offset']:x}")

    strings = printable_strings(data)
    findings = classify_strings(strings)

    if findings["xlm_functions"]:
        print("\n[Potential XLM Functions / Keywords]")
        for x in findings["xlm_functions"]:
            print(f"  {x}")

    if findings["lolbins"]:
        print("\n[Potential LOLBins / Executables]")
        for x in findings["lolbins"]:
            print(f"  {x}")

    if findings["command_fragments"]:
        print("\n[Command Fragments Worth Correlating]")
        for x in findings["command_fragments"]:
            print(f"  {x}")

    if findings["file_refs"]:
        print("\n[File / Payload References]")
        for x in findings["file_refs"]:
            print(f"  {x}")

    if findings["urls"]:
        print("\n[URLs]")
        for x in findings["urls"]:
            print(f"  {x}")

    if findings["domains"]:
        print("\n[Domain-Like Strings]")
        for x in findings["domains"]:
            print(f"  {x}")

    if args.strings:
        print("\n[All Extracted Printable Strings]")
        for x in strings:
            print(f"  {x}")

    print("\n[Analyst Reminder]")
    print("  Output is evidence for triage, not a verdict.")
    print("  A discovered string, URL, executable, DLL, or function does not prove execution.")
    print("  Follow references, establish the execution chain, and correlate with other evidence.")
    print("  If the result exposes something new, pivot the investigation instead of forcing a fixed checklist.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
