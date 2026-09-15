# 🛡️ SOC Analyst Journey: From Network & Host Analysis to SIEM Triage

An intensive, hands-on 12-week roadmap designed to build practical core competencies for **Tier-1 SOC Analyst** and **Junior Blue Team** roles. This repository tracks lab write-ups, incident investigation notes, forensic artifacts, custom detection rules, and automated tooling developed throughout this curriculum.

---

## 🎯 Target Milestones (Target Completion: December 1, 2026)

- [ ] **Packet & Host Forensics**: Fluently analyze network sessions in Wireshark and interpret Windows Event Logs (`4624`, `4625`, `4720`), Sysmon events (`ID 1`, `ID 3`), and Linux syslog records.
- [ ] **Centralized SIEM & Triage**: Master SPL/KQL query syntax on Splunk & Elastic, triaging and closing 8–10 real-world alert tickets on LetsDefend adhering to standard incident playbooks.
- [ ] **Home Lab Deployment**: Architect an isolated multi-node telemetry pipeline (Endpoint -> Forwarder -> SIEM) simulating adversary tactics and host defenses.
- [ ] **Detection & Automation**: Develop lightweight Python scripts automating IOC enrichment via VirusTotal and AbuseIPDB APIs.

---

## 🗓️ 12-Week Structured Curriculum

### Month 1: Raw Telemetry, Packet Analysis & Host Investigation
*Focus: Deep-dive into unaggregated packet captures (`.pcap`) and low-level operating system logs.*

* **Week 1 — Network Forensics with Wireshark**
  * Display filter operations: HTTP method isolation, TCP stream reconstruction, and DNS inspection.
  * Reconnaissance triage: Distinguishing between open (`SYN, ACK`), closed (`RST, ACK`), and filtered (packet dropped/retransmitted) port states under TCP SYN stealth scans.
  * Cleartext exfiltration: Inspecting unencrypted application sessions (HTTP `POST`) to extract sensitive artifacts.
* **Week 2 — Windows Security Internals & Sysmon**
  * Critical Windows Event IDs: `4624` (Logon types: Type 2 Interactive, Type 3 Network, Type 10 RDP), `4625` (Brute-Force patterns), `4672` (Privilege assignment), and `4720` (Account creation).
  * Advanced host visibility via Sysmon: Process creation tracking (`Event ID 1`: CLI switches, `ParentImage`) and network connection correlation (`Event ID 3`).
  * Practical investigation: Completing TryHackMe Windows Event Logs lab scenarios.
* **Week 3 & 4 — Linux Telemetry & Phishing Email Investigation**
  * Linux audit trails: Inspecting `/var/log/auth.log` (or `secure`) for SSH brute-force attempts; log filtering via `grep`, `awk`, and `cut`.
  * Email header forensics: Validating sender authenticity using SPF, DKIM, and DMARC records.
  * Phishing triage: Extracting suspicious URLs/attachments, defanging indicators, de-obfuscating payloads via CyberChef, and reputation cross-referencing via VirusTotal.

---

### Month 2: Centralized SIEM Operations & Live Incident Response
*Focus: Transforming raw log ingestion into actionable alerts, triage decisions, and alert closure.*

* **Week 5 & 6 — Enterprise SIEM (Splunk & Elastic / Kibana)**
  * Core Search Processing Language (SPL): Query optimization with `index=`, `sourcetype=`, `stats count by`, `eval`, and `transaction`.
  * Correlation logic: Constructing alert rules based on behavioral anomalies (e.g., triggering alerts on >5 failed logons `4625` within 60 seconds followed by a successful `4624`).
  * Hands-on labs: TryHackMe Splunk Basics and ELK 101 modules.
* **Week 7 & 8 — Live Incident Handling & Ticket Management (LetsDefend)**
  * SOC L1 workflows: Alarm notification -> Telemetry collection -> Host/Network artifact isolation -> Containment & eradication recommendations.
  * Case study execution: Investigating 8–10 structured cases covering Endpoint Brute-Force, Phishing Deliveries, and Malware Outbreaks.
  * Portfolio documentation: Documenting complete post-incident triage write-ups for two comprehensive cases (1 Phishing, 1 Malware/Web Attack).

---

### Month 3: Detection Engineering, Lab Deployment & Tooling
*Focus: Building detection infrastructure, writing automation scripts, and packaging deliverables.*

* **Week 9 & 10 — SOC Home Lab Deployment**
  * Virtualized environment setup (VirtualBox / VMware):
    * **Simulated Attacker:** Kali Linux / Adversary script generator.
    * **Monitored Endpoint:** Windows 10/11 client with Sysmon and Winlogbeat/Splunk Universal Forwarder.
    * **Telemetry Core:** Ubuntu Server hosting Splunk Enterprise / Elastic Stack.
  * Attack simulation & validation: Executing simulated reconnaissance and credential abuse to verify real-time dashboard visualization.
* **Week 11 — SecOps Scripting & IOC Enrichment (Python)**
  * Developing an automated IOC triage utility (<50 lines):
    * Reads lists of suspicious IPs, domains, or file hashes.
    * Queries the VirusTotal / AbuseIPDB REST APIs for threat scores.
    * Exports triage metrics directly into structured `.csv` reports for analysts.
* **Week 12 — Technical Portfolio Packaging & Professional Review**
  * Consolidating investigation reports, lab architectural diagrams, and script repositories.
  * Publishing professional technical write-ups to validate competencies for summer 2027 internship cycles.

---

## 💡 Core Competencies & Key Analytical Takeaways

Through this iterative 12-week progression, the following analytical principles and engineering perspectives are established:

1. **Dual-Lens Visibility (Network vs. Endpoint Synchronization)**
   * Packet captures provide unimpeachable evidence of traffic in transit, but modern transport layer encryption (TLS/HTTPS) masks payload contents. 
   * Correlating network indicators (e.g., beaconing intervals or unexpected outbound ports) with host-level telemetry (Sysmon `Event ID 1` and `3`) provides the necessary contextual link between external connections and the exact process running in memory.

2. **Alert Triaging & Triage Discipline**
   * High alert volume demands structured qualification. Determining a True Positive (TP) versus a False Positive (FP) requires corroborating multiple artifacts (matching hashes, checking command-line flags, verifying domain reputations) rather than relying solely on automated threat scoring.

3. **Detection Architecture & The Pipeline Lifecycle**
   * Threat hunting and rule engineering are built upon understanding log pipelines. Deploying collectors (Winlogbeat/Forwarders) demonstrates how bandwidth limits, log parsing, and timestamp discrepancies impact triage clarity in enterprise SOC environments.

4. **SecOps Automation Mindset**
   * Manual threat intelligence lookups for every event are unsustainable at scale. Building custom Python enrichment scripts highlights how API integration can eliminate analyst fatigue by automating repetitive data gathering during initial triage stages.

---

## 🛠️ Tools & Technologies Used
* **Traffic & Protocol Analysis:** Wireshark, TShark, CyberChef.
* **Host Telemetry & Auditing:** Windows Event Viewer, Sysmon, Linux CLI (`auth.log`, `syslog`).
* **SIEM Platforms:** Splunk Enterprise, Elastic Stack (Elasticsearch, Kibana).
* **Investigation Platforms:** LetsDefend.io, TryHackMe.
* **Scripting & OS Platforms:** Python 3, PowerShell, Bash, Ubuntu Linux, Windows 10/11.
