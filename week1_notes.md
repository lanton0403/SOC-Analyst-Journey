# Incident Investigation Report: Network Reconnaissance & Cleartext Data Leakage

## 1. Executive Summary
During traffic triage across multiple packet capture datasets (`nmap_OS_scan_succesful` and an HTTP file upload session), two critical security events were identified:
1. **Network Reconnaissance:** An external host conducted an automated TCP SYN port scan against internal server `192.168.100.101`, enumerating active SMB services (ports 139, 445).
2. **Cleartext Exfiltration / Policy Violation:** An internal client transmitted unencrypted application data (`alice.txt`) over HTTP Port 80 via a multipart `POST` request, exposing sensitive local directory paths and payload contents.

---

## 2. Case 1: TCP SYN Port Scanning (Half-Open Reconnaissance)

### Incident Artifacts
* **Analysis Tool:** Wireshark v4.x
* **Attacker IP:** `192.168.100.103`
* **Victim IP:** `192.168.100.101`
* **Scan Method:** TCP SYN (Stealth / Half-Open) Scan

### Technical Findings & Port State Categorization
Analysis of the TCP handshake indicators revealed three distinct network states:
* **Open Ports (SMB Services):**
  * **Observed Behavior:** The target host replied with `SYN, ACK`. The scanner immediately aborted the connection by transmitting a `RST` packet, completing reconnaissance without establishing a full application session.
  * **Identified Services:** Port 139 (`netbios-ssn`), Port 445 (`microsoft-ds`).
* **Closed Ports:**
  * **Observed Behavior:** Target kernel replied immediately with `RST, ACK`, confirming no listener service was bound to the probed ports.
* **Filtered Ports:**
  * **Observed Behavior:** The target host yielded no response. The scanner performed 1 to 2 SYN retransmissions before timing out, confirming traffic dropping by firewall/filtering controls.

### Key Display Filters
* Detect inbound SYN probes:  
  `tcp.flags.syn == 1 && tcp.flags.ack == 0`
* Isolate open port responses:  
  `ip.src == 192.168.100.101 && tcp.flags.syn == 1 && tcp.flags.ack == 1`
* Isolate closed port reset responses:  
  `tcp.flags.reset == 1 && tcp.flags.ack == 1`

---

## 3. Case 2: Unencrypted HTTP File Upload & Stream Reconstruction

### Incident Artifacts
* **Protocol:** HTTP/1.1 (TCP Port 80)
* **Request URI:** `POST /ethereal-labs/lab3-1-reply.htm`
* **Destination Host:** `gaia.cs.umass.edu`
* **Content-Type:** `multipart/form-data; boundary=---------------------------7d537442b03aa`
* **Payload Size:** 152,372 bytes

### Technical Findings & Forensic Reconstruction
* **Data Extraction:** By utilizing Wireshark's **Follow TCP Stream**, the raw application layer payload was reconstructed without requiring decryption keys.
* **Artifact Leakage:** 
  * The multipart boundary header leaked the absolute local file path of the client machine:  
    `C:\bchoi\class\CS4411-5651-Spr05\Labs\ethereal\alice.txt`
  * The entire textual payload (*Alice's Adventures in Wonderland*) was recovered in plain text.
* **Server Acknowledgment:** The remote server returned `HTTP/1.1 200 OK` confirming successful upload receipt (`"You've now transferred a copy of alice.txt..."`).
* **Protocol Scope Observation:** While **Export Objects -> HTTP** successfully extracts structured HTTP files, non-HTTP tunneling protocols (such as raw DNS command shells in `dns-remoteshell.pcap`) do not populate the HTTP object table and require direct query inspection (`dns.flags.response == 0`).

---

## 4. SOC Analytical & Transport Layer Takeaways
* **Triage Workflow:** High-volume traffic analysis starts broad via `Statistics -> Conversations` (IPv4) to isolate top talkers, followed by targeted display filters, and concludes with stream reconstruction (`Follow TCP Stream`).
* **Header Architecture:** Layer 3 addresses (32-bit IPv4) handle network routing, while Layer 4 ports (16-bit) and Sequence/Acknowledgment numbers ensure stream reassembly and packet reliability.
* **Cleartext Risk:** All legacy cleartext protocols (HTTP, FTP, Telnet) permit passive eavesdropping and trivial payload recovery.

---

## 5. Defensive Recommendations
1. **Firewall Filtering:** Configure perimeter firewalls to silently `DROP` probes on non-essential ports instead of issuing `RST, ACK` packets, denying attackers visibility into live IP ranges.
2. **SMB Hardening:** Restrict Port 139 and Port 445 traffic strictly to internal management subnets; block all SMB exposure at boundary interfaces.
3. **Mandatory Encryption:** Enforce HTTPS/TLS across all web traffic to mitigate cleartext eavesdropping and prevent data exfiltration visibility over port 80.