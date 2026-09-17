# Tool Reference: OSINT & Threat Intelligence (Search Skills)

Fast reference documentation for open-source intelligence platforms and technical research utilities used during security alert triage and incident correlation.

---

## 1. Shodan (Network & Device Search Engine)

* **Purpose:** Banner grabbing and indexing Internet-connected devices to identify exposed attack surfaces, misconfigured services, and unpatched versions.
* **Core Filter Operators:**
  * `port:<number>`: Restrict results to a specific open port (e.g., `port:22`, `port:3389`).
  * `country:<2-letter-code>`: Filter hosts by geographic location (e.g., `country:VN`, `country:DE`).
  * `org:"<Organization>"`: Target IP ranges assigned to a specific organization or Autonomous System Number (ASN).
  * `hostname:<domain>`: Match banner records tied to explicit domain names or host records.
* **Defensive Takeaway:** Web servers (such as Apache HTTP Server) must suppress verbose server banners (`ServerTokens Prod`, `ServerSignature Off`) to prevent remote adversaries from indexing specific software versions tied to critical CVEs.

---

## 2. VirusTotal (Multi-Engine Artifact Reputation)

* **Purpose:** Centralized threat aggregation platform evaluating files, hashes, domains, and IP addresses across 70+ antivirus engines and threat intelligence feeds.
* **SOC Application:** Extract cryptographic hashes (SHA256, MD5) from process telemetry (Sysmon Event ID 1) or file creation events (Sysmon Event ID 11) to distinguish benign system binaries from malware payloads without manual sandboxing.

---

## 3. Vulnerability Databases (CVE & NVD)

* **Purpose:** Standardized indexing system for publicly known security vulnerabilities via Common Vulnerabilities and Exposures identifiers (e.g., `CVE-2024-21413`).
* **Evaluation Metrics:**
  * **CVSS Score:** Base score (0.0 to 10.0) reflecting vulnerability severity, exploit complexity, and impact on Confidentiality, Integrity, and Availability.
  * **Exploit Availability:** Validating public availability of Proof-of-Concept (PoC) exploits on platforms like GitHub or Exploit-DB to establish incident containment priority.

---

## 4. Linux Terminal Documentation (`man`)

* **Purpose:** Built-in command manual pages enabling immediate parameter and flag verification directly inside the shell environment.
* **SYNOPSIS Syntax Convention:**
  * Square brackets `[...]`: Denotes optional flags and parameters.
  * Bare tokens without brackets: Denotes mandatory arguments (e.g., `destination`, `port`).
* **Essential Navigation:**
  * `/<keyword>`: Search forward for specific parameters or switches.
  * `n` / `N`: Jump to next / previous search match.
  * `q`: Terminate and exit the manual viewer.

  ---

## 5. GitHub for Threat Intelligence & Research

* **Purpose:** Open-source code repository utilized by defenders to monitor the threat landscape, track newly disclosed exploit mechanics, and deploy community-maintained detection rules.
* **SOC Use Cases:**
  * **Proof of Concept (PoC) Analysis:** Reviewing published exploit code to identify how an attacker triggers a specific CVE, exposing required prerequisites, payload structures, and expected network or endpoint signatures.
  * **Detection Engineering:** Sourcing public detection assets such as community **Sigma rules**, **YARA rules**, and adversary emulation scripts (e.g., Atomic Red Team) to build alerting logic before vendors push native patches.
  * **OSINT & Sensitive Data Discovery:** Checking for accidental credential leakage, API tokens, internal IP ranges, or hardcoded secrets left behind by internal developers in public repositories.
* **Operational Caution:** Never execute untrusted PoC code from public repositories directly on production or unisolated analysis environments, as adversaries frequently distribute fake PoCs weaponized with backdoor loaders.