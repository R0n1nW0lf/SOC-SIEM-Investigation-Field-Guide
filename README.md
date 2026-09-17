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

**Investigation chain:**

`WAF alert → Request → WAF action → HTTP response → Did it reach the application? → Application/endpoint evidence → Determine actual impact`

**Analyst mindset:**

> **Detection tells you where to investigate. The WAF action and correlated evidence tell you what actually happened.**

## Firewall Traffic Log Quick Reference

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


## Purpose

This repository is part of my cybersecurity portfolio and demonstrates how I organize and apply SOC investigation concepts during authorized training and lab environments.

## Disclaimer

All examples and techniques documented here are based on authorized cybersecurity training, lab environments, and defensive security analysis.

## Ongoing Development

This field guide is a living document.

I will continue adding new investigation techniques, attack patterns, indicators, search methods, and lessons learned as I progress through additional SOC labs and hands-on cybersecurity investigations.

The goal is to continuously improve this guide based on practical experience rather than treat it as a finished reference.
