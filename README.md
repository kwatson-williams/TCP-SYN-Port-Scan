# TCP-SYN-Port-Scan

## Overview

This lab presents a full **network forensics investigation** of a suspicious packet capture (`Task #1003.pcapng`) obtained from the Blue Team Labs Online (BTLO) platform. The analysis uncovers a **distributed TCP SYN Port Scan** targeting an internal host, demonstrates how to distinguish real threats from false leads, and concludes with concrete mitigation recommendations. The entire investigation was conducted using Wireshark.

---

## Executive Summary

During the investigation of `Task #1003.pcapng`, suspicious network traffic was analyzed to identify potential security threats. The investigation revealed that an internal device (`10.2.2.8`) was the target of a **distributed TCP SYN Port Scan**. This activity involved multiple external IP addresses systematically attempting to identify open ports on the victim machine. Internal ARP traffic was also investigated but determined to be benign. This report details the methodology, findings, and recommendations to mitigate these risks.

---

## Table of Contents

- [Step 1 — Setting Up the Analysis Environment](#step-1--setting-up-the-analysis-environment)
- [Step 2 — Protocol Hierarchy Analysis](#step-2--protocol-hierarchy-analysis)
- [Step 3 — Conversations Analysis (IPv4 & Ethernet)](#step-3--conversations-analysis-ipv4--ethernet)
- [Step 4 — Display Filter Isolation](#step-4--display-filter-isolation)
- [Step 5 — Visual Color Coding & ARP Observation](#step-5--visual-color-coding--arp-observation)
- [Step 6 — Anomalies & Indicators of Compromise (IOCs)](#step-6--anomalies--indicators-of-compromise-iocs)
- [Step 7 — Deep Packet Analysis & SYN Flood Confirmation](#step-7--deep-packet-analysis--syn-flood-confirmation)
- [Step 8 — Addressing False Leads](#step-8--addressing-false-leads)
- [Step 9 — Summarized Findings & Recommendations](#step-9--summarized-findings--recommendations)
- [Summary Table](#summary-table)
- [Tools & Technologies](#tools--technologies)

---

## Step 1 — Setting Up the Analysis Environment

**Opening and Configuring the PCAP File**

The capture file `Task #1003.pcapng` was downloaded from the BTLO platform and opened in Wireshark. The file was verified to contain **337,461 packets**, indicating a significant volume of network traffic requiring careful analysis.

Upon initial inspection, the packet list revealed a mix of standard protocols including **TCP, TLS, and DNS**, providing a starting baseline for the investigation.

<img width="1489" height="906" alt="step1_opening_pcap" src="https://github.com/user-attachments/assets/5b72828b-f2d6-4e2b-b866-645279662a0a" />

---

## Step 2 — Protocol Hierarchy Analysis

**Tool Used:** `Statistics > Protocol Hierarchy`

The Protocol Hierarchy tool was used to understand the overall distribution of traffic within the capture. This technique helps quickly narrow focus to the dominant protocol and rule out irrelevant traffic types.

**Key Findings:**
- **99.6% of all traffic was TCP**, confirming the network activity was almost entirely connection-oriented.
- No high-risk file-sharing protocols (e.g., BitTorrent) were present.
- No clear-text administrative protocols (e.g., Telnet) were observed, helping to focus the investigation specifically on **TCP anomalies**.

![Step 2 — Protocol Hierarchy Statistics](tcp_images/step2_protocol_hierarchy.png)

---

## Step 3 — Conversations Analysis (IPv4 & Ethernet)

**Tool Used:** `Statistics > Conversations`

The Conversations tool was used across both **IPv4 and Ethernet** layers to identify high-volume talkers and map the relationships between internal and external IP addresses.

This step was critical in uncovering the attack pattern — it revealed that a single internal host (`10.2.2.8`) was communicating with dozens of unique external IPs, which is highly abnormal behavior consistent with a coordinated scanning effort.

![Step 3 — Conversations Tool (IPv4)](tcp_images/step3_conversations_ipv4.png)

---

## Step 4 — Display Filter Isolation

**Filters Applied:**
```
ip.addr == 10.2.2.8
tcp.flags.syn == 1
```

Wireshark display filters were applied to strip away background noise and focus exclusively on traffic involving the suspected victim machine (`10.2.2.8`) and SYN-flagged TCP packets. This isolation technique is essential for cutting through hundreds of thousands of packets to surface only the relevant attack traffic.

These filters confirmed that the internal host was receiving a large volume of inbound SYN packets from many different external sources — a definitive indicator of a port scan.

![Step 4 — Display Filters Applied](tcp_images/step4_display_filters.png)

---

## Step 5 — Visual Color Coding & ARP Observation

**Technique:** Wireshark Default Color Rules

Wireshark's built-in color coding was used to visually identify protocol anomalies within the traffic stream. During this phase, a **yellow-highlighted ARP packet** (Packet 27) was noticed amidst the standard TCP traffic, triggering further investigation.

The ARP packet stood out as a potential **"Man-in-the-Middle" spoofing attempt**, prompting a deeper look before it was ruled out as a false lead in a later step.

![Step 5 — Color Coding & ARP Packet Identification](tcp_images/step5_color_coding_arp.png)

---

## Step 6 — Anomalies & Indicators of Compromise (IOCs)

**Tool Used:** `Statistics > Conversations`

Using the Conversations tool, a highly suspicious and mechanically consistent pattern was identified targeting `10.2.2.8`:

| IOC Indicator | Value |
|---------------|-------|
| **Target Host** | `10.2.2.8` |
| **Attack Type** | Distributed TCP SYN Port Scan |
| **Packets per Connection** | Exactly **2 packets** |
| **Bytes per Connection** | Exactly **108 bytes** |
| **Example Source IPs** | `7.11.164.28`, `11.28.194.89`, and dozens more |

The mechanical consistency of **exactly 2 packets and 108 bytes per connection** across dozens of unique external IPs is a strong **Indicator of Compromise (IOC)**. This uniformity is characteristic of an **automated scanning tool**, not human-initiated behavior.

![Step 6 — IOC Pattern in Conversations](tcp_images/step6_ioc_pattern.png)

---

## Step 7 — Deep Packet Analysis & SYN Flood Confirmation

**Filter Applied:**
```
ip.dst == 10.2.2.8 && tcp.flags.syn == 1
```

A targeted display filter was applied to confirm the nature of the attack at the packet level. The filtered results revealed a **flood of [SYN] packets** all targeting **Port 80 (HTTP)** on the victim machine (`10.2.2.8`).

**Technical Conclusion:**

This confirms a **TCP SYN Port Scan**. The attackers were sending the initial TCP handshake request (`SYN`) to probe whether Port 80 was open — without completing the three-way handshake. The high volume of requests from many different external source IPs indicates a **coordinated, distributed reconnaissance effort** designed to map the organization's network defenses.

![Step 7 — SYN Flood Packets Targeting Port 80](tcp_images/step7_syn_flood_confirmation.png)

---

## Step 8 — Addressing False Leads

Two false leads were investigated and ruled out during the analysis.

### False Lead 1 — Internal Complicity
- **Assumption:** Internal hosts `10.2.2.5` and `10.2.2.8` were initially suspected of communicating maliciously due to both being highly active.
- **Correction:** A display filter for direct traffic between them returned **zero results**. The Conversations tool confirmed that `10.2.2.5` was performing normal web browsing (Google/Cloudflare), while `10.2.2.8` was being externally attacked.

### False Lead 2 — The Yellow ARP Packet
- **Assumption:** The yellow ARP packet (Packet 27) was suspected as a potential **Man-in-the-Middle ARP spoofing** attempt due to the sudden protocol change.
- **Correction:** Deep analysis revealed this was simply `10.2.2.5` asking *"Who has 10.2.2.1?"* (the default gateway) — a **completely standard network function** required for internet access. Identifying this as benign allowed focus to return to the external threat.

![Step 8 — ARP False Lead Analysis](tcp_images/step8_false_lead_arp.png)

---

## Step 9 — Summarized Findings & Recommendations

### Security Incident Summary

The investigation confirms that the network was subjected to an **external Reconnaissance Attack**. The internal host `10.2.2.8` was being actively scanned on **Port 80** by a botnet or distributed group of attackers. No successful data exfiltration was observed in this capture, but the scanning indicates that attackers were searching for vulnerabilities to exploit.

### Mitigation Recommendations

| Priority | Action | Details |
|----------|--------|---------|
| 🔴 **High** | **Firewall Blocking** | Configure the perimeter firewall to block ingress traffic from the suspicious external IP ranges identified in the scan |
| 🔴 **High** | **Port Hardening** | If `10.2.2.8` does not need to host a public web server, **close Port 80 immediately** to eliminate the attack surface. Migrate to **Port 443 (HTTPS)** for secure connections |
| 🟡 **Medium** | **IDS Rule Implementation** | Deploy an Intrusion Detection System rule to alert administrators when a single internal IP receives SYN packets from more than **10 unique external sources within a 1-minute window** |

---

## Summary Table

| Step | Action | Tool / Technique |
|------|--------|-----------------|
| 1 | Downloaded and opened `Task #1003.pcapng` (337,461 packets) | Wireshark |
| 2 | Analyzed protocol distribution — 99.6% TCP confirmed | Statistics > Protocol Hierarchy |
| 3 | Mapped high-volume talkers and IP relationships | Statistics > Conversations |
| 4 | Isolated victim traffic and SYN packets | Display Filters (`ip.addr`, `tcp.flags.syn`) |
| 5 | Identified ARP anomaly via color coding | Wireshark Color Rules |
| 6 | Discovered IOC pattern — 2 packets / 108 bytes per external IP | Statistics > Conversations |
| 7 | Confirmed TCP SYN Port Scan targeting Port 80 | Deep Packet Analysis |
| 8 | Ruled out internal complicity and ARP spoofing as false leads | Display Filters + Packet Inspection |
| 9 | Documented findings and issued mitigation recommendations | Analysis Report |

---

## Tools & Technologies

| Tool | Purpose |
|------|---------|
| [Wireshark](https://www.wireshark.org/) | Full packet capture analysis, filtering, conversations, protocol hierarchy |
| [BTLO (Blue Team Labs Online)](https://blueteamlabs.online/) | Challenge platform providing the `Task #1003.pcapng` capture file |
| Wireshark Display Filters | Traffic isolation (`ip.addr`, `tcp.flags.syn`, `ip.dst`) |
| Wireshark Conversations Tool | Identifying high-volume talkers and IOC patterns |
| Wireshark Color Rules | Visual anomaly detection (ARP, TCP resets, etc.) |

---

## Category

| | |
|-|-|
| **Type** | Network Forensics / Threat Detection / Reconnaissance Analysis |
| **Difficulty** | Intermediate |
| **Platform** | Blue Team Labs Online (BTLO) |
| **Attack Type** | Distributed TCP SYN Port Scan |
| **Victim Host** | `10.2.2.8` |
| **Targeted Port** | Port 80 (HTTP) |
