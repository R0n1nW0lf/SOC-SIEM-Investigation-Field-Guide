# SOC/SIEM Investigation Field Guide

A practical SOC/SIEM investigation field guide developed from hands-on security labs and investigation exercises.

## About This Project

This field guide documents my approach to investigating security alerts, analyzing logs, identifying attack indicators, determining whether an attack was successful, and making escalation and containment decisions.

The guide is designed as a quick-reference resource for SOC investigations and will continue to grow as I complete additional hands-on labs and investigations.

## Topics Covered

- SOC alert triage and investigation workflow
- HTTP status codes and response analysis
- Brute-force and authentication attacks
- Directory traversal and LFI
- RFI and SSRF identification
- Open redirection
- IDOR
- XXE
- Phishing investigation
- Process and network correlation
- C2 investigation
- IOC and artifact identification
- Successful vs. attempted attack determination
- Tier 2 escalation and containment decisions
- Analyst note documentation
- SIEM/EDR-first investigation methodology
- Dynamic malware analysis
- Windows Registry hive shorthand and persistence paths
- TCP flags and connection-state interpretation
- Wireshark investigation filters
- WAF alert and action interpretation
- Firewall traffic log analysis and NGFW application identification

## Investigation Philosophy

Start with the evidence already available in the SIEM and EDR.

**SIEM / EDR → Correlate Evidence → Deeper Analysis → Sandbox if Needed**

Sandboxing, packet analysis, and static malware analysis are useful when existing telemetry is insufficient, but they should not replace evidence already available in the SIEM.

---

# Field Guide — Part 2

> **Continuation Notice:** This section is Part 2 of the SOC/SIEM Investigation Field Guide and continues the material contained in `SOC_SIEM_Investigation_Field_Guide.docx`. It adds new hands-on investigation techniques, lessons learned, and reference material from authorized cybersecurity labs and training.

## Dynamic Malware Analysis

Dynamic malware analysis involves executing a suspicious file inside an isolated lab environment and observing its runtime behavior. The objective is to determine what the sample actually does, including process activity, file creation, Registry modification, persistence, and network communication.

**Investigation chain:**

`Execute → Processes → Files → Registry → Network → Persistence → C2 → Indicators`

### Dynamic Analysis Tool Reference

| Tool | Primary Use |
| --- | --- |
| Procmon | Runtime process, file system, Registry, and related activity |
| Process Hacker | Processes, parent/child relationships, handles, DLLs, and network connections |
| Regshot | Before-and-after Registry comparison |
| Wireshark | DNS, TCP/UDP, IP addresses, ports, and packet analysis |
| Fiddler | HTTP/HTTPS application traffic inspection |
| HashMyFiles | Generate and compare file hashes |
| ANY.RUN | Historical or live sandbox evidence, process/network correlation, and application-layer traffic when behavior cannot be reproduced locally |

### Procmon — Detecting Dropped Files

Recommended capture routine:

`Clear old events → Start Capture → Execute Sample → Stop Capture → Filter`

Filtering after capture does not erase the captured evidence. Avoid over-filtering by the original sample name because malware may be renamed or a child process may perform additional activity.

Useful filters and operations include:

- `Process Name is <sample.exe>`
- `Path contains AppData`
- `CreateFile`
- `WriteFile`

**File-drop investigation pattern:**

`Malware process → AppData path → CreateFile / WriteFile → dropped executable`

Procmon can show file activity, but it does not calculate the file's cryptographic hash. Use a hashing tool when the investigation requires MD5, SHA-1, or SHA-256.

### Procmon — Include the Malware Parent and Children

Filtering only by the original malware process can cause important evidence to be missed. Malware may launch or abuse another process, including legitimate Windows binaries such as `RegSvcs.exe`. A child process may perform network communication, file activity, Registry modification, or other malicious behavior instead of the original executable.

In Procmon:

**Tools → Process Tree → locate the malware parent process → right-click → Add process and children to Include filter**

Then review the filtered events for activity such as:

- `Process Create`
- `TCP Connect`
- `TCP Send`
- `TCP Receive`
- `CreateFile`
- `WriteFile`
- `RegSetValue`
- `RegCreateKey`

This filter does **not guarantee** that Procmon will reveal the final answer. It is a strong clue that narrows the investigation to processes and events more likely to be related to the sample. Always correlate the results with other evidence sources.

### Wireshark — Malware Network Activity

Start by identifying unusual DNS queries and correlate them with subsequent network connections.

**Network investigation pattern:**

`DNS query → Domain → Resolved IP → TCP connection → Destination port → Application traffic`

When reading a TCP connection such as:

`50145 → 587`

`50145` is the temporary client/source port and `587` is the destination/service port.

A TCP `[SYN]` indicates the beginning of a connection attempt. Use **Follow TCP Stream** when necessary to inspect the complete conversation. Port `587` commonly represents SMTP message submission.

### When Wireshark Does Not Show the Evidence You Need

Wireshark is extremely useful for packet-level investigation, but it will not always provide every piece of evidence needed to answer an investigation question.

A connection may be short-lived, encrypted, use a non-standard port, rely on cached DNS information, or the remote infrastructure may no longer be active. A capture can also contain large amounts of unrelated background traffic that make the relevant activity difficult to identify.

For example, malware may previously have exfiltrated data through an SMTP server. If that mail server is no longer online, executing the malware today may never reproduce the original SMTP traffic. Wireshark cannot capture traffic that never occurs.

When required behavior cannot be reproduced, use another evidence source rather than guessing. Alternative sources may include:

- ANY.RUN or another authorized malware sandbox
- EDR or network telemetry
- Historical PCAP files
- Procmon
- Process Hacker or similar process inspection tools
- SIEM logs
- Previously recorded sandbox reports

The goal is not to force one tool to answer every question. The goal is to **correlate evidence across tools**.

A useful investigation pattern is:

`Known event → Timestamp → Victim IP → Protocol → Destination → Follow Stream → Correlate with process evidence`

A matching packet by itself is not proof that something is malicious. For example:

`SYN → retransmission → retransmission`

with no `SYN/ACK` means the connection was attempted but was not established. Do not mistake a failed connection attempt for successful communication or exfiltration.

### Wireshark Investigation Filter Cheat Sheet

Large packet captures contain significant background traffic. Start broad, then narrow the capture with display filters instead of manually reading every packet.

For domain hunting, `dns` shows DNS queries and responses. When responses create too much noise, use:

`dns.flags.response == 0`

This shows **DNS queries only**, making it much easier to identify domains requested by the host. Review unusual domains in context rather than assuming the first unfamiliar domain is malicious.

**Useful Wireshark display filters:**

| Investigation Goal | Display Filter |
| --- | --- |
| All DNS traffic | `dns` |
| DNS queries only | `dns.flags.response == 0` |
| DNS A-record traffic | `dns.qry.type == 1` |
| HTTP traffic | `http` |
| HTTP requests only | `http.request` |
| TLS traffic | `tls` |
| SMTP traffic | `smtp` |
| TCP traffic | `tcp` |
| UDP traffic | `udp` |
| Traffic involving an IP | `ip.addr == <IP>` |
| Traffic sent from an IP | `ip.src == <IP>` |
| Traffic sent to an IP | `ip.dst == <IP>` |
| Traffic involving a TCP port | `tcp.port == <PORT>` |
| Traffic sent to a TCP port | `tcp.dstport == <PORT>` |
| SYN packets | `tcp.flags.syn == 1` |
| Initial SYN without ACK | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Reset packets | `tcp.flags.reset == 1` |
| FIN packets | `tcp.flags.fin == 1` |
| TCP retransmissions | `tcp.analysis.retransmission` |
| ARP traffic | `arp` |
| ICMP traffic | `icmp` |

Filters can be combined with `&&` for **AND**, `||` for **OR**, and `!` for **NOT**. Examples:

`ip.addr == <IP> && tcp`

`ip.src == <IP> && dns`

`ip.src == <VICTIM_IP> && tcp`

`frame.time_relative >= <START> && frame.time_relative <= <END>`

`tcp.port == 25 || tcp.port == 465 || tcp.port == 587`

`tcp.dstport == 587 || smtp`

**Analyst workflow:**

`Broad capture → Filter protocol → Identify suspicious host/domain/IP → Narrow by IP/port → Follow Stream → Correlate with process evidence`

A useful filter reduces the haystack; it does not determine whether the remaining traffic is malicious. Always correlate network findings with process, file, Registry, endpoint, and timeline evidence.

### Large Log Files — Filter Instead of Opening

Very large logs can overwhelm or crash GUI text editors and lab environments. When working with a large file, avoid loading the entire log into an editor when the investigation only requires a specific field, value, or pattern. Use streaming command-line tools such as `awk`, `grep`, `sort`, `uniq`, and `less` to reduce the data first.

For example, after verifying that the requesting/source IP is the third whitespace-separated field:

```bash
awk '{print $3}' http.log | sort | uniq -c | sort -nr | head
```

This extracts the source-IP field, groups identical values, counts them, sorts the counts from highest to lowest, and displays the highest-requesting IPs.

**Workflow:**

`Confirm log structure → Extract relevant field → Count/group values → Sort results → Investigate the highest-interest entries → Verify against raw evidence`

For targeted review:

```bash
grep "KEYWORD" http.log | less
```

Use `less` when browsing a large log without loading the entire file into a normal GUI editor.

> **Large-log rule: Do not read a massive log line by line when the question can be answered by filtering and aggregation. Preserve the raw log, reduce the haystack, then investigate the evidence that matters.**

#### Reusable Large-Log Command Reference

First confirm the log structure before choosing a field number:

```bash
head -n 5 <LOGFILE>
```

Then substitute the verified field number for `<FIELD>`. Do **not** assume that IP addresses, ports, methods, status codes, or other values always occupy the same column across different log formats.

| Investigation Goal | Reusable Syntax |
| --- | --- |
| Top/most frequent values in any verified field | `awk '{print $<FIELD>}' <LOGFILE> \| sort \| uniq -c \| sort -nr \| head` |
| Top source/requesting IPs | `awk '{print $<SRC_IP_FIELD>}' <LOGFILE> \| sort \| uniq -c \| sort -nr \| head` |
| Top destination IPs | `awk '{print $<DST_IP_FIELD>}' <LOGFILE> \| sort \| uniq -c \| sort -nr \| head` |
| Top source ports | `awk '{print $<SRC_PORT_FIELD>}' <LOGFILE> \| sort \| uniq -c \| sort -nr \| head` |
| Top destination ports | `awk '{print $<DST_PORT_FIELD>}' <LOGFILE> \| sort \| uniq -c \| sort -nr \| head` |
| Top HTTP methods | `awk '{print $<METHOD_FIELD>}' <LOGFILE> \| sort \| uniq -c \| sort -nr \| head` |
| Top HTTP status codes | `awk '{print $<STATUS_FIELD>}' <LOGFILE> \| sort \| uniq -c \| sort -nr \| head` |
| Top requested URI/path values | `awk '{print $<URI_FIELD>}' <LOGFILE> \| sort \| uniq -c \| sort -nr \| head` |
| Search a specific IP | `grep -F '<IP>' <LOGFILE> \| less` |
| Search a specific port/value | `grep -F '<VALUE>' <LOGFILE> \| less` |
| Search attack/method/status keywords | `grep -Ei '<KEYWORD1>\|<KEYWORD2>\|<KEYWORD3>' <LOGFILE> \| less` |

**Placeholder key:**

- `<LOGFILE>` = log filename/path, for example `http.log`
- `<FIELD>` = verified whitespace-separated field/column number
- `<SRC_IP_FIELD>` = verified source/requesting-IP field number
- `<DST_IP_FIELD>` = verified destination-IP field number
- `<SRC_PORT_FIELD>` = verified source-port field number
- `<DST_PORT_FIELD>` = verified destination-port field number
- `<METHOD_FIELD>` = verified HTTP-method field number
- `<STATUS_FIELD>` = verified HTTP-response/status field number
- `<URI_FIELD>` = verified requested URI/path field number
- `<IP>` = IP address being investigated
- `<VALUE>` = exact port, domain, user, hash, status code, or other value
- `<KEYWORD#>` = one or more investigation keywords or patterns

**Analyst reminder:** The reusable syntax is the pattern; the field numbers come from the actual log format. Verify the structure first, then substitute the correct field references.

#### Exact Field Search — Count What the Field Actually Means

A broad keyword search can overcount because the same word may appear in another field, URI, message, User-Agent, payload, or other text. When the investigation asks specifically for a method, action, status, result, or another structured value, verify its field number and count the exact field value.

First identify the field position from a known matching record:

```bash
grep -m 1 -w '<VALUE>' <LOGFILE> | awk '{for(i=1;i<=NF;i++) print i,$i}'
```

Then count only records where that verified field exactly matches the value:

```bash
awk '$<FIELD>=="<VALUE>" {count++} END {print count}' <LOGFILE>
```

Examples after the correct field numbers have been verified:

```bash
awk '$<METHOD_FIELD>=="DELETE" {count++} END {print count}' <LOGFILE>
awk '$<ACTION_FIELD>=="REJECT" {count++} END {print count}' <LOGFILE>
awk '$<ACTION_FIELD>=="DENY" {count++} END {print count}' <LOGFILE>
awk '$<ACTION_FIELD>=="ALLOW" {count++} END {print count}' <LOGFILE>
awk '$<STATUS_FIELD>==200 {count++} END {print count}' <LOGFILE>
awk '$<STATUS_FIELD>==301 {count++} END {print count}' <LOGFILE>
awk '$<STATUS_FIELD>==302 {count++} END {print count}' <LOGFILE>
awk '$<STATUS_FIELD>==403 {count++} END {print count}' <LOGFILE>
awk '$<STATUS_FIELD>==404 {count++} END {print count}' <LOGFILE>
awk '$<STATUS_FIELD>=500 && $<STATUS_FIELD><600 {count++} END {print count}' <LOGFILE>
```

For HTTP status categories, after verifying the status field:

```bash
awk '$<STATUS_FIELD>=200 && $<STATUS_FIELD><300 {count++} END {print count}' <LOGFILE>   # 2xx successful HTTP responses
awk '$<STATUS_FIELD>=300 && $<STATUS_FIELD><400 {count++} END {print count}' <LOGFILE>   # 3xx redirects
awk '$<STATUS_FIELD>=400 && $<STATUS_FIELD><500 {count++} END {print count}' <LOGFILE>   # 4xx client errors
awk '$<STATUS_FIELD>=500 && $<STATUS_FIELD><600 {count++} END {print count}' <LOGFILE>   # 5xx server errors
```

To inspect rather than count exact field matches:

```bash
awk '$<FIELD>=="<VALUE>"' <LOGFILE> | less
```

To see the most common values in a verified field:

```bash
awk '{print $<FIELD>}' <LOGFILE> | sort | uniq -c | sort -nr | head
```

**Additional placeholder keys:**

- `<ACTION_FIELD>` = verified action/result field such as `ALLOW`, `DENY`, `DROP`, `REJECT`, `SUCCESS`, or `FAILED`
- `<METHOD_FIELD>` = verified HTTP method field such as `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, or `TRACE`
- `<STATUS_FIELD>` = verified numeric HTTP response/status field
- `<VALUE>` = exact value being investigated

**Real lab lesson:** A broad `grep -w "DELETE"` search returned 227 matching lines, while exact field analysis returned 223 records where the HTTP-method field was actually `DELETE`. The extra keyword occurrences were not DELETE-method requests.

> **Keyword occurrence ≠ field-specific event. For large structured logs, verify the field and query that field directly before reporting a count.**

> **Large-file safety: Filter and aggregate from the command line instead of loading a massive log into a GUI text editor. This reduces memory pressure and avoids unnecessary crashes while preserving the original log for verification.**


#### Carve Large Logs into Smaller Working Files

When a raw log is extremely large, create smaller filtered **working copies** for the part of the investigation being examined. Keep the original log unchanged.

After verifying the relevant field numbers, examples include:

```bash
# HTTP-method records only
awk '$<METHOD_FIELD>=="GET" || $<METHOD_FIELD>=="POST" || $<METHOD_FIELD>=="PUT" || $<METHOD_FIELD>=="DELETE" || $<METHOD_FIELD>=="HEAD" || $<METHOD_FIELD>=="OPTIONS" || $<METHOD_FIELD>=="TRACE" || $<METHOD_FIELD>=="CONNECT"' <LOGFILE> > HTTP-only.log

# Records for one source/requesting IP
awk '$<SRC_IP_FIELD>=="<IP>"' <LOGFILE> > HTTP-IP.log

# One IP plus one exact HTTP method
awk '$<SRC_IP_FIELD>=="<IP>" && $<METHOD_FIELD>=="DELETE"' <LOGFILE> > HTTP-IP-DELETE.log
```

Compare file sizes and record counts:

```bash
ls -lh <LOGFILE> HTTP-only.log HTTP-IP.log HTTP-IP-DELETE.log
wc -l <LOGFILE> HTTP-only.log HTTP-IP.log HTTP-IP-DELETE.log
```

**Investigation funnel:**

`Large raw log → Relevant records → Relevant IP → Relevant method/activity → Smaller working evidence set`

The filtered files are investigation aids, not replacements for the source evidence. Preserve the original log unchanged and verify important findings against it before reporting.

> **Carve the haystack; preserve the haystack.**



### Know When to Pivot

If expected evidence is absent, do not immediately assume the activity never happened.

First determine whether the connection failed, the capture missed it, another process performed it, the traffic is encrypted or not decoded as expected, or the original infrastructure is no longer available. Then pivot to another evidence source.

In one authorized malware-analysis exercise, the current Wireshark capture showed the malware contacting its public-IP lookup service, but the historical SMTP exfiltration could no longer be reproduced. The investigation therefore moved to a historical ANY.RUN analysis, where the process, remote connection, SMTP traffic, and authentication sequence could be correlated.

**Analyst mindset:**

> **Use each tool for the evidence it can provide. If one source reaches a dead end, pivot to another source and correlate the results. Never fill missing evidence with assumptions.**

### TCP Flag Quick Reference

The normal TCP three-way handshake is:

`SYN → SYN/ACK → ACK`

This establishes the connection before application data is exchanged.

| Flag | Meaning | Analyst Interpretation |
| --- | --- | --- |
| `SYN` | Synchronize | Begins a TCP connection attempt |
| `SYN, ACK` | Synchronize + acknowledge | Server acknowledges the connection request and responds |
| `ACK` | Acknowledge | Confirms received TCP data or completes the handshake |
| `PSH` | Push | Requests that received data be delivered to the application promptly |
| `PSH, ACK` | Push + acknowledge | Common during active application-data exchange |
| `FIN` | Finish | Gracefully begins closing a TCP connection |
| `FIN, ACK` | Finish + acknowledge | Common during normal connection teardown |
| `RST` | Reset | Abruptly terminates or rejects a TCP connection |

A simplified normal conversation may look like:

`SYN → SYN/ACK → ACK → PSH/ACK → PSH/ACK → FIN/ACK`

Think of the sequence as:

`Connect → Established → Exchange Data → Close`

`FIN` and `PSH` are not inherently suspicious. Interpret TCP flags in context with the source and destination hosts, ports, process, protocol, timestamps, and application behavior.

### Regshot — Registry Comparison

Recommended workflow:

`1st Shot → Execute Sample → 2nd Shot → Compare`

Review the comparison for:

- Keys added
- Values added
- Values modified

For persistence investigations, search for the dropped executable name and common startup locations such as `CurrentVersion\Run` and `CurrentVersion\RunOnce`. Correlate the Registry value with the executable it references.

## Windows Registry Hive Shorthand

Different Windows tools may display the same Registry hive using different names. When reviewing Regshot, Procmon, Registry Editor, SIEM, or EDR evidence, translate the shorthand before comparing paths or answering a lab question.

| Shorthand | Full Registry Hive |
| --- | --- |
| `HKU` | `HKEY_USERS` |
| `HKCU` | `HKEY_CURRENT_USER` |
| `HKLM` | `HKEY_LOCAL_MACHINE` |
| `HKCR` | `HKEY_CLASSES_ROOT` |
| `HKCC` | `HKEY_CURRENT_CONFIG` |

### Important HKU / HKCU Relationship

A tool such as Regshot may show a user's key as:

`HKU\<USER-SID>\Software\Microsoft\Windows\CurrentVersion\Run`

When that SID belongs to the currently logged-in user, the corresponding friendly path is:

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

`HKU` itself means `HKEY_USERS`. Do not automatically translate every `HKU` path to `HKEY_CURRENT_USER`; confirm that the SID belongs to the current user.

### Persistence Correlation

A common user-level persistence location is:

`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

The equivalent current-user SID form may appear as:

`HKU\<CURRENT-USER-SID>\Software\Microsoft\Windows\CurrentVersion\Run`

Programs referenced by values under this key can be launched when that user logs on. During malware analysis, correlate the Registry value data with the dropped executable path before concluding that it is the malware's persistence mechanism.

**Investigation chain:**

`Dropped executable → Registry Run value → executable path matches → persistence evidence`

### Dynamic Analysis Rule

Do not rely on one artifact. Correlate behavior across the available evidence.

**`Process → File → Registry → Network → Persistence → IOC`**

Preserve evidence before remediation or resetting the lab. Start with the evidence that directly answers the investigation question, then go deeper only when necessary.

## WAF Investigation Quick Reference

A Web Application Firewall (WAF) evaluates inbound HTTP/HTTPS application traffic against configured rules and can allow, block, deny, or challenge requests before they reach the web application.

**WAF investigation rule:** A WAF alert proves that a suspicious web request was detected. It does **not** by itself prove that exploitation succeeded.

When investigating a WAF alert, check:

- Source and destination
- HTTP method and requested URI
- WAF action: `ALLOW`, `BLOCK`, `DENY`, or `CHALLENGE`
- HTTP status code and response details
- Whether the request reached the application
- Application/server logs for resulting behavior
- Endpoint/EDR evidence when relevant

**Interpretation:**

- `403 Forbidden` together with a confirmed WAF block is strong evidence that the request was stopped at the WAF.
- `200 OK` means the request was processed successfully at the HTTP level, but **does not by itself prove exploitation succeeded**.
- A malicious request that was `ALLOW`ed requires deeper investigation to determine whether the application was affected.
- Misconfigured WAF rules can cause false positives by blocking legitimate requests or false negatives by allowing malicious requests through.

### HTTP Status Code Quick Reference

When HTTP response status is available in WAF, proxy, web-server, IDS/IPS, or SIEM evidence, highlight the status code and its category so the analyst can quickly identify how the application/server responded.

| Range / Code | Meaning | Analyst Attention |
| --- | --- | --- |
| `100–199` | Informational | Request/response processing information |
| `200–299` | Successful HTTP response | Request was successfully handled at the HTTP level; this does **not** by itself prove an attack succeeded |
| `300–399` | Redirection | Request was redirected; review the destination/location and surrounding request |
| `400–499` | Client error | Request was rejected, invalid, unauthorized, forbidden, or content was not found depending on the exact code |
| `500–599` | Server error | Server/application encountered an error or could not complete the request |

Common examples:

- `200 OK` → successful HTTP response
- `301 Permanent Redirect` → redirected to another location
- `403 Forbidden` → requested access was forbidden
- `404 Not Found` → requested content was not found
- `503 Service Unavailable` → service/server was unavailable

**Highlighting rule:** Make status codes visually distinct and show their category beside them, for example `200 → SUCCESSFUL RESPONSE`, `301 → REDIRECTION`, `403 → CLIENT ERROR / FORBIDDEN`, and `503 → SERVER ERROR / SERVICE UNAVAILABLE`.

> **HTTP success ≠ exploit success. HTTP failure/error ≠ automatic proof an attack was blocked by the WAF. Correlate the response code with WAF action, request content, application logs, and other evidence.**

### Web Attack URL Pattern Quick Reference

When reviewing WAF, proxy, web-server, IDS/IPS, or SIEM logs, inspect the requested URL/URI and parameters for attack-related patterns. These strings are investigation indicators and should be correlated with the WAF action, HTTP response, application logs, and other evidence before determining whether exploitation succeeded.

| Attack Type | Example Analyst-Interest Patterns |
| --- | --- |
| HTML Injection | HTML tags such as `<h1>`, `</h1>`, or other markup inserted into parameters |
| XSS | Script markup such as `<script>`, `</script>`, or URL-encoded equivalents |
| SQL Injection | SQL syntax such as `'`, `UNION`, `SELECT`, `OR 1=1`, `--`, `CHR(...)`, and encoded equivalents such as `%27` |
| Directory Traversal | Repeated `../` or encoded traversal sequences leading toward files such as `/etc/passwd` |

**Useful review/highlight keywords and patterns:**

`<script>`, `</script>`, `<h1>`, `</h1>`, `UNION`, `SELECT`, `OR 1=1`, `CHR(`, `--`, `../`, `/etc/passwd`, `%2F`, `%27`, `PUT`, `DELETE`, `TRACE`, `CONNECT`, `OPTIONS`

HTTP methods such as `PUT`, `DELETE`, `TRACE`, `CONNECT`, and `OPTIONS` should be surfaced for analyst review when present. These methods can be legitimate; treat them as analyst-interest indicators when their use is unexpected for the application rather than automatically labeling them malicious. Correlate the method with the URI, source, authentication context, WAF action, HTTP response, and application behavior.

URL encoding or character-building functions can hide the readable form of a request. Preserve the original request and, when useful, create a separate decoded working representation for analysis. For example, a sequence of `CHR(number)` expressions can be decoded separately while the original expression remains available for verification.

> **Keyword match ≠ successful exploitation. Highlight the pattern, decode/reconstruct when needed, then verify what actually happened using the surrounding evidence.**

**Investigation chain:**

`WAF alert → Request → WAF action → HTTP response → Did it reach the application? → Application/endpoint evidence → Determine actual impact`

**Analyst mindset:**

> **Detection tells you where to investigate. The WAF action and correlated evidence tell you what actually happened.**

## Firewall Traffic Log Quick Reference

### Firewall / Security Control Type Memory Reference

Use the name of the control as a quick clue for what kind of traffic or evidence it primarily examines.

| Type | Memory Hook | Primary Focus |
| --- | --- | --- |
| **WAF — Web Application Firewall** | **WAF = WEB** | HTTP/HTTPS web-application traffic such as methods, URLs/URIs, parameters, headers, status codes, SQLi, XSS, and other web attacks |
| **Network Firewall** | **Firewall = network traffic control** | Source/destination IPs, ports, protocols, interfaces, connection state, and allow/deny/drop/reject decisions |
| **NGFW — Next-Generation Firewall** | **NGFW = network + application awareness** | Traditional firewall traffic plus application identification and additional security inspection depending on the product |
| **IDS — Intrusion Detection System** | **IDS = Detect + Alert** | Detects suspicious network activity and alerts; normally does not prevent the traffic itself |
| **IPS — Intrusion Prevention System** | **IPS = Detect + Prevent** | Detects suspicious network activity and can block/drop/prevent matching traffic |

**Quick memory:** `WAF → WEB | Firewall → Network | NGFW → Network + Application | IDS → Detect | IPS → Prevent`

These are general memory hooks. Exact capabilities, inspection depth, and actions depend on the product and configuration.

For SOC investigations, the most critical firewall logs are generally the traffic logs that record communications passing through the firewall.

### Key Firewall Log Fields

| Field | Meaning |
| --- | --- |
| `date` | Event date |
| `time` | Event time |
| `devname` | Firewall/device hostname |
| `devid` | Device identifier |
| `eventtime` | Event timestamp, often in device/vendor format |
| `tz` | Time zone |
| `logid` | Log/event identifier |
| `type` | Log type, such as traffic or event |
| `subtype` | Log subtype, such as forward, system, or other vendor-defined category |
| `level` | Log severity/level |
| `srcip` | Source IP address |
| `srcname` | Source hostname, when available |
| `srcport` | Source port |
| `srcintf` | Source interface name |
| `srcintfrole` | Role of the source interface |
| `dstip` | Destination IP address |
| `dstport` | Destination port |
| `dstintf` | Destination interface name |
| `dstintfrole` | Role of the destination interface |
| `srccountry` | Source IP geographic/country information |
| `dstcountry` | Destination IP geographic/country information |
| `action` | Firewall decision/action, such as allow, accept, deny, drop, or reject |
| `service` | Identified service information |
| `transip` | NAT-translated IP address |
| `transport` | NAT-translated port |
| `duration` | Connection/session duration |
| `sentbyte` | Number of bytes sent |
| `rcvdbyte` | Number of bytes received |
| `sentpkt` | Number of packets sent |
| `rcvdpkt` | Number of packets received |

**Fast investigation chain:**

`Time → Source → Destination → Port/Service → Interface → Action → NAT → Duration → Bytes/Packets → Correlate`

Bytes, packet counts, and duration provide useful context about the amount and direction of communication, but they should be interpreted with the firewall action, connection state, protocol/application, and other evidence before determining impact.

### Firewall Log Field Quick Reference

Use this compact grouping when reading raw firewall traffic logs:

**Identity/time:** `date`, `time`, `devname`, `devid`, `logid`, `type`, `subtype`

**Traffic:** `srcip`, `srcport`, `srcintf` → `dstip`, `dstport`, `dstintf`

**Decision/context:** `action`, `service`, `srccountry`, `dstcountry`

**NAT:** `transip`, `transport`

**Connection evidence:** `duration`, `sentbyte`, `rcvdbyte`, `sentpkt`, `rcvdpkt`

**Mental reference:**

`When/which device? → Who talked to whom? → What service/action? → Was NAT used? → How much communication occurred?`


### Firewall Block Response

A firewall can block traffic without necessarily notifying the sender. Distinguish between a silent drop and an active rejection when interpreting firewall behavior.

- `DROP` → silently discards traffic; typically no explicit rejection response is returned to the sender.
- `REJECT` → actively rejects the traffic and normally returns a response indicating that the connection cannot proceed.
- `DENY` → behavior can depend on the firewall vendor and configuration. Verify the product, rule behavior, and logs before assuming whether a response was sent.

**Analyst rule:**

> **Blocked ≠ sender was necessarily notified. Determine whether the firewall silently dropped or actively rejected the traffic.**

### Unique Value Check

When an investigation asks for **different**, **unique**, or **open** destination ports, do not count repeated `dstport` entries as separate ports.

Example:

`443, 1521, 53, 443 → 3 unique destination ports, not 4`

Multiple firewall log events can represent repeated activity against the same destination port. Distinguish the **number of events/attempts** from the **number of unique ports**.

This same check can also apply to repeated IP addresses, domains, users, processes, hashes, and other indicators when the investigation asks for unique values.

**Analyst reminder:**

> **Event count ≠ unique value count. Check for duplicates before reporting the total.**


### NGFW Application Awareness

A Next-Generation Firewall (NGFW) can identify application-layer traffic rather than relying only on port numbers. Do not automatically assume that a service is being used simply because traffic uses its common port.

For example:

`Destination Port: 443 | Application: SSH | Action: DENY`

Port `443` commonly carries HTTPS, but if the NGFW identifies the application as SSH, investigate the traffic as SSH activity rather than assuming it is HTTPS based only on the port.

**Analyst rule:**

> **Port number is a clue, not proof of the application. When application-aware firewall telemetry is available, correlate the port with the identified application/protocol and the surrounding evidence.**

## IDS / IPS Log Analysis Quick Reference

### IDS vs. IPS

- **IDS — Intrusion Detection System:** Detects suspicious network activity and generates alerts for analyst review.
- **IPS — Intrusion Prevention System:** Detects suspicious network activity and can take a configured preventive action such as blocking or dropping traffic.

Both can use signature databases containing rules designed to identify known attack patterns. A signature match tells the analyst that traffic matched a detection rule; it does **not** by itself prove that an attack succeeded.

**Investigation chain:**

`IDS/IPS alert → Signature → Source/Destination → Ports/Protocol → Action → Payload/Context → Correlate other evidence → Determine what happened`

### Common IDS / IPS Alert Fields

IDS/IPS alarm output commonly includes network and detection information such as:

| Field | Analyst Use |
| --- | --- |
| Timestamp | When the event occurred |
| Source / Destination IP | Which systems were communicating |
| Source / Destination Port | Network endpoints and likely service context |
| Protocol | TCP, UDP, ICMP, or application protocol when identified |
| Signature / Signature ID | Rule that triggered the alert |
| Category / Severity | Vendor or ruleset classification and priority |
| Action | Whether traffic was allowed, alerted, dropped, blocked, or otherwise handled |
| Payload / Printable Payload | Packet/application content when captured and available |
| Interface / VLAN | Network location/context when logged |

**Parent process information is normally not part of a network IDS/IPS alert.** Parent/child process relationships generally come from endpoint telemetry such as EDR, Sysmon, Process Hacker, or other host/process-monitoring sources. Correlate endpoint evidence with the IDS/IPS event when process context is needed.

### Direction Matters

Do not assume an IDS/IPS event represents the original request. Use source/destination addresses and ports to determine traffic direction.

For DNS, for example:

`Client ephemeral port → DNS server port 53 = query/request direction`

`DNS server port 53 → Client ephemeral port = response/return direction`

A signature containing `NXDOMAIN Response` indicates a DNS response associated with a non-existent-domain result. Keep the conclusion within the evidence shown by the event; do not infer unrelated historical activity from a single alert.

### IDS / IPS Analyst Rule

> **A signature match is a detection clue, not proof of successful compromise. Read the action, direction, payload, and surrounding evidence before determining impact.**

---

## VPN Log Analysis Quick Reference

VPN authentication logs are easier to investigate when the raw events are reconstructed into a simple sequence.

**Primary pivots:**

`Timestamp → User → Remote/Public IP → Source Region → Authentication Result → Tunnel/Session Activity`

### Reconstruct Unclear Logs for Analysis

When a raw log is difficult to read, keep the **original log unchanged** and reconstruct or reformat a **separate working copy** into a layout that is easier to analyze.

A practical method is to paste the working copy into **Notepad++** and separate, align, search, or highlight the fields that matter to the investigation.

For example, convert a dense VPN log into:

`Timestamp | User | Source IP | Region | Result`

This can make repeated events, time intervals, failures, successes, duplicate values, and other patterns much easier to recognize.

**Workflow:**

`Preserve original evidence → Create separate working copy → Paste into Notepad++ → Reconstruct important fields → Analyze patterns → Verify findings against original log`

**Analyst rule:**

> **Reconstruct for readability, not to change the evidence. Keep the original raw log available and verify conclusions against it before reporting.**

This technique can also be used with firewall, proxy, authentication, EDR, and other dense text logs.


### Authentication Timeline and Brute-Force Pattern

Do not evaluate repeated login failures only as isolated events. Use timestamps to determine their sequence, frequency, and spacing.

A pattern such as:

`Failure → Failure → Failure → Failure → Success`

for the **same account and source IP within a short time window** is consistent with password guessing or brute-force activity and should be investigated further. The pattern alone does not prove account compromise.

A successful authentication after repeated failures is especially important because it may indicate that a credential was eventually accepted. Pivot from that successful login into the VPN session and correlate subsequent activity.

**Investigation chain:**

`Same user → Same source IP → Repeated failures → Short time intervals → Successful login → Investigate session activity`

**Analyst reminder:**

> **Timestamps are evidence of sequence. They can turn separate authentication failures into a recognizable behavior pattern.**

### VPN Address Correlation

- `remip` or equivalent remote/public IP fields identify where the VPN connection originated.
- `tunnelip`, when assigned and logged by the VPN, can be used as a pivot to correlate the authenticated VPN session with subsequent internal network activity.

**Correlation chain:**

`User → Remote IP → Authentication result → Tunnel IP → Internal activity`

VPN routing, split tunneling, NAT, and vendor configuration can affect which address appears in downstream logs, so verify the environment rather than assuming every event will expose the tunnel IP.


## SIEM Log Collection, Parsing, and Correlation Quick Reference

### Collection Methods

| Method | Quick Reference |
| --- | --- |
| Agent-based | Software on the source collects/forwards logs and may parse, buffer, encrypt, or check integrity |
| Agentless | Collects remotely without a local agent; may use methods such as SSH or WMI |
| Script/custom collection | Useful when an existing collector cannot retrieve a required log source |
| Syslog | Common log-transport method; can use UDP or TCP and may support TLS depending on implementation |

**Memory reference:** `Agent → local collector | Agentless → remote collection | Script → custom collection | Syslog → transport`

Examples from training include **Splunk Universal Forwarder** and **ArcSight Connectors**.

> **Visibility rule: If the SIEM never receives the log source, the analyst cannot rely on the SIEM to detect or correlate activity from that missing telemetry. When expected evidence is absent, verify that the source is actually being collected.**

### Aggregation, Parsing, and Enrichment

- **Aggregation** → bring logs from multiple sources into a central location/SIEM.
- **Parsing** → break raw log data into meaningful fields such as timestamp, source IP, destination IP, port, user, action, or status.
- **Filtering** → retain or surface the records needed for the use case.
- **Enrichment** → add useful context such as geolocation or DNS/reverse-DNS information.

**Workflow:** `Collect → Aggregate → Parse → Normalize/Enrich → Index → Correlate/Search → Analyst Review`

### Preserve Original Time — Normalize a Working View

Different log sources may use different date formats or time zones. Normalizing timestamps can make cross-source timeline correlation easier, but preserve the original evidence.

Example working representation:

`Original: 2026-09-19 23:30 UTC → Analyst view: 2026-09-19 19:30 EDT`

> **Analyst rule: Modify the working/normalized view, not the raw evidence. Preserve the original timestamp and timezone so converted values can always be verified.**

### Indexing and Search

Indexing is important because it allows stored SIEM data to be searched and retrieved efficiently. With large log volumes, **search speed** directly affects how quickly an analyst can pivot through evidence.

**Memory reference:** `Index → faster search/retrieval`

### Long-Tail Analysis

Long-tail analysis gives attention to **rare or least-common events** because unusual activity can be hidden among large volumes of normal repetitive events.

Rare does **not** automatically mean malicious.

**Analyst rule:** `Rare event → higher investigation interest → correlate context → determine meaning`

### Correlation Example — Brute Force

A correlation pattern such as:

`Same source IP → 15 failed logins → 1 minute`

is consistent with brute-force/password-guessing behavior and should be investigated.

The rule identifies a behavior pattern; it does not by itself prove compromise. If a successful login follows the failures, pivot into the resulting session and correlate subsequent activity.

### Hash Blacklist Limitation

A file hash identifies file content, not its filename. Renaming or copying a file does not normally change its hash, while modifying the file contents does.

**Memory reference:** `Rename/copy ≠ new hash | Content modification → new hash`

Hash blacklists are therefore useful for known files but should not be the only detection method.

### Whitelist / Allowlist Concept

An allowlist permits only explicitly approved items. This can provide strong control but can require significant maintenance as legitimate systems, software, and business requirements change.

**Memory reference:** `Allowlist → known good allowed → effective control, higher management effort`


## SIEM EPS Quick Reference

**EPS = Events Per Second** — the number of log/events a SIEM receives or processes each second.

When a log rate is given per minute:

`Events per minute ÷ 60 = EPS`

Example:

`150,000 logs per minute ÷ 60 = 2,500 EPS`

**Memory reference:** `Logs/min ÷ 60 → EPS`


## Purpose

This repository is part of my cybersecurity portfolio and demonstrates how I organize and apply SOC investigation concepts during authorized training and lab environments.

## Disclaimer

All examples and techniques documented here are based on authorized cybersecurity training, lab environments, and defensive security analysis.

## Ongoing Development

This field guide is a living document.

I will continue adding new investigation techniques, attack patterns, indicators, search methods, and lessons learned as I progress through additional SOC labs and hands-on cybersecurity investigations.

The goal is to continuously improve this guide based on practical experience rather than treat it as a finished reference.
