# Week 01: Network Protocols & Wireshark Triage Cheat Sheet

A condensed operational guide covering core Layer 3/4 transport mechanics, display filter syntax, port scanning triage, and cleartext forensic analysis for SOC Analysts.

---

## 1. Transport Layer & Protocol Mechanics

### The TCP Three-Way Handshake & Teardown
* **Connection Establishment:**
  1. `Client -> Server`: `SYN` (Synchronize flag set; client selects an Initial Sequence Number `ISN_c`).
  2. `Server -> Client`: `SYN, ACK` (Acknowledges `ISN_c + 1`; server provides its own `ISN_s`).
  3. `Client -> Server`: `ACK` (Acknowledges `ISN_s + 1`; bidirectional session established).
* **Connection Termination:**
  * **Graceful Teardown:** `FIN` -> `ACK` -> `FIN` -> `ACK` (Four-way handshake).
  * **Abrupt Reset (`RST`):** Tears down the connection immediately without waiting for unacknowledged data in transit. Triggered on unexpected packets, half-open scans, or closed ports.

### Host Responses & Port States
| Port State | Server Response | Operational Interpretation |
| :--- | :--- | :--- |
| **Open** | `SYN, ACK` | A daemon/service is actively listening and ready to accept connections. |
| **Closed** | `RST, ACK` | The host is live, but no active service is bound to the queried port. |
| **Filtered** | *No response* (Silent drop) | A firewall, security group, or packet filter dropped the probe; client initiates TCP retransmissions before timing out. |

---

## 2. Reconnaissance & Triage Patterns

### TCP SYN (Half-Open / Stealth) Scan
* **Behavior:** The scanner sends a raw `SYN` packet.
  * If the port responds with `SYN, ACK` (Open), the scanner immediately responds with a `RST` to tear down the embryonic session before completing the 3-way handshake.
  * Avoids application-level service logging (e.g., web server access logs), but remains fully visible in packet-level monitoring.
* **Filter to Isolate Incoming Probes:**  
  `tcp.flags.syn == 1 && tcp.flags.ack == 0`
* **Filter to Identify Open Ports Responding:**  
  `ip.src == [Target_IP] && tcp.flags.syn == 1 && tcp.flags.ack == 1`

### Cleartext Data Exfiltration & Payload Leakage
* Unencrypted protocols (`HTTP`, `FTP`, `Telnet`, `DNS`) transmit payloads directly across Layer 4/7 without cryptographic envelopes.
* Multipart `POST` requests expose not only file bodies (e.g., text, binaries) but also client-side filesystem artifacts such as local directory paths in `Content-Disposition` headers.

---

## 3. Essential Wireshark Display Filters

### Traffic Scoping & Addressing
* **By Host Address:**
  * `ip.addr == 192.168.1.10` (Matches both inbound and outbound traffic)
  * `ip.src == 192.168.1.100 && ip.dst == 10.0.0.5` (Unidirectional stream)
* **By Layer 4 Port:**
  * `tcp.port == 80 || tcp.port == 443` (Web traffic)
  * `tcp.dstport == 445` (Targeted SMB enumeration probes)

### TCP Flags Matching Syntax
* **Pure SYN (Connection Init / Scan Probes):**  
  `tcp.flags.syn == 1 && tcp.flags.ack == 0`
* **SYN-ACK (Session Acceptance / Open Port Proof):**  
  `tcp.flags.syn == 1 && tcp.flags.ack == 1`
* **RST Combinations (Reset / Rejection):**  
  * Any Reset: `tcp.flags.reset == 1`
  * Closed Port Response: `tcp.flags.reset == 1 && tcp.flags.ack == 1`
* **Null Scan Probes:**  
  `tcp.flags == 0`
* **FIN Scan Probes:**  
  `tcp.flags == 0x001`

### Application Layer Protocols
* **HTTP:**
  * Specific Methods: `http.request.method == "POST"` or `http.request.method == "GET"`
  * Status Codes: `http.response.code >= 400` (Client/Server errors)
  * Payload Inspection: `frame contains "password"` or `http contains "filename="`
* **DNS:**
  * Outbound Queries: `dns.flags.response == 0`
  * Specific Record Lookups: `dns.qry.type == 16` (TXT record queries, common in DNS tunneling)
  * High-Length Subdomain Indicators: `frame contains ".c2domain.com"`

---

## 4. Analyst Workflows & Verification Shortcuts

* **Identify Top Talkers:** Navigate to `Statistics` -> `Conversations` -> `IPv4` tab. Sort by `Bytes` or `Packets` to quickly isolate high-bandwidth or high-volume scanners.
* **Full Session Reconstruction:** Right-click any packet -> `Follow` -> `TCP Stream` (Shortcut: `Ctrl + Alt + Shift + T`). Reassembles out-of-order segments into a linear plain-text transcript.
* **Direct File Extraction:** Navigate to `File` -> `Export Objects` -> `HTTP` to pull reassembled cleartext artifacts (HTML, binaries, uploaded scripts) directly from memory.