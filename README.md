# Network Security and Firewall Monitoring System (CSA0712)

**Course Code:** CSA0712 – Computer Networks / Network Security  
**Student Name:** Dharanidaran D  
**Register Number:** 192521337  

---

## 📌 Project Overview

The **Network Security and Firewall Monitoring System** is a Python-based network security simulation designed to demonstrate core packet-filtering, access control, and intrusion detection concepts. The system inspects incoming and outgoing network packets, enforces administrator-defined firewall rules, identifies suspicious traffic patterns (such as DoS/flooding attacks and unauthorized port probes), logs security events, and presents real-time analytics via a Network Traffic Dashboard.

---

## ✨ Key Features

* **Packet Inspection & Filtering:** Evaluates network traffic using `Source IP`, `Destination IP`, `Port Number`, and `Protocol (TCP/UDP)` against a prioritized rule table with a **Default-Deny** security posture.
* **Dynamic Firewall Rule Management:** Allows administrators to dynamically insert custom `ALLOW` or `BLOCK` rules.
* **Suspicious Activity & DoS Detection:** Tracks per-IP request frequency to detect volumetric flooding attacks and flags probes targeting insecure ports (e.g., Telnet port `23`).
* **Automated Security Alerts:** Generates real-time alerts whenever threshold breaches or unauthorized access attempts occur.
* **Persistent Security Logging:** Automatically records all permitted and blocked packet events with timestamps into `firewall_security.log`.
* **Network Traffic Dashboard:** Displays a structured summary of total packets, allowed vs. blocked counts, active security alerts, and packet-level inspection logs.

---

## 📂 Repository Structure

```text
CSA0712-192521337-Firewall-Monitor/
│
├── firewall_monitor.py       # Main Python implementation (Firewall Engine, IDS & Dashboard)
├── firewall_security.log     # Auto-generated persistent security log file
└── README.md                 # Project documentation and usage guide
```

---

## 🛠️ Prerequisites & Setup

* **Language:** Python 3.8 or higher
* **Dependencies:** Uses Python Standard Library modules only (`time`, `random`, `datetime`, `collections`). No external packages are required.

### Installation & Execution

1. **Clone the repository:**
   ```bash
   git clone https://github.com<your-username>/CSA0712-192521337-Firewall-Monitor.git
   cd CSA0712-192521337-Firewall-Monitor
   ```

2. **Run the Firewall Monitoring System:**
   ```bash
   python firewall_monitor.py
   ```

---

## ⚙️ Default Firewall Ruleset

| Priority | Rule Name | Source IP | Destination IP | Port | Protocol | Action |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: |
| 1 | `Allow_Admin_SSH` *(Dynamic)* | `192.168.1.10` | `10.0.0.5` | `22` | TCP | **ALLOW** |
| 2 | `Block_Blacklisted_IP` | `192.168.1.50` | `ANY` | `ANY` | ANY | **BLOCK** |
| 3 | `Block_External_SSH` | `ANY` | `10.0.0.5` | `22` | TCP | **BLOCK** |
| 4 | `Block_Telnet_Insecure` | `ANY` | `10.0.0.5` | `23` | TCP | **BLOCK** |
| 5 | `Allow_HTTP_Web` | `ANY` | `10.0.0.5` | `80` | TCP | **ALLOW** |
| 6 | `Allow_HTTPS_Secure` | `ANY` | `10.0.0.5` | `443` | TCP | **ALLOW** |
| 7 | `Allow_DNS_Query` | `ANY` | `10.0.0.5` | `53` | UDP | **ALLOW** |
| 8 | `Default_Deny_All` | `ANY` | `ANY` | `ANY` | ANY | **BLOCK** |

---

## 📊 Sample Output

### Network Traffic Dashboard
```text
===============================================================================================
                 NETWORK SECURITY & FIREWALL MONITORING DASHBOARD
===============================================================================================
Total Packets: 11  |  Allowed: 3  |  Blocked: 8  |  Security Alerts: 1
-----------------------------------------------------------------------------------------------
Source IP       Dest IP      Port   Proto  Type      Status    Firewall Rule          Suspicious Activity
-----------------------------------------------------------------------------------------------
192.168.1.10    10.0.0.5     22     TCP    Incoming  ALLOWED   Allow_Admin_SSH        Normal
203.0.113.45    10.0.0.5     22     TCP    Incoming  BLOCKED   Block_External_SSH     Normal
198.51.100.12   10.0.0.5     443    TCP    Incoming  ALLOWED   Allow_HTTPS_Secure     Normal
10.0.0.5        8.8.8.8      53     UDP    Outgoing  ALLOWED   Allow_DNS_Query        Normal
192.168.1.50    10.0.0.5     80     TCP    Incoming  BLOCKED   Block_Blacklisted_IP   Normal
172.16.0.99     10.0.0.5     23     TCP    Incoming  BLOCKED   Block_Telnet_Insecure  Unauthorized Service Probe
45.33.22.11     10.0.0.5     80     TCP    Incoming  BLOCKED   Auto_DoS_Mitigation    DoS / High Traffic Flood

===============================================================================================
ACTIVE SECURITY ALERTS:
 [!] SECURITY ALERT: Potential DoS/Flooding detected from 45.33.22.11 (Packets: 5)
===============================================================================================
```

---

## 🎯 Learning Outcomes

* Practical understanding of **stateless packet filtering** and **Access Control Lists (ACLs)**.
* Implementation of a **Default-Deny** security policy to minimize attack surfaces.
* Detection and automated mitigation of **Denial-of-Service (DoS)** traffic bursts.
* Structured security event auditing and traffic visualization.
