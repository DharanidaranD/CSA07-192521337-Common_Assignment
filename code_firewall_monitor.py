import time
import random
from datetime import datetime
from collections import defaultdict

class FirewallMonitoringSystem:
    def __init__(self):
        # Default Firewall Rules: (Src_IP, Dst_IP, Port, Protocol, Action, Rule_Name)
        self.rules = [
            ("192.168.1.50", "ANY", "ANY", "ANY", "BLOCK", "Block_Blacklisted_IP"),
            ("ANY", "10.0.0.5", 22, "TCP", "BLOCK", "Block_External_SSH"),
            ("ANY", "10.0.0.5", 23, "TCP", "BLOCK", "Block_Telnet_Insecure"),
            ("ANY", "10.0.0.5", 80, "TCP", "ALLOW", "Allow_HTTP_Web"),
            ("ANY", "10.0.0.5", 443, "TCP", "ALLOW", "Allow_HTTPS_Secure"),
            ("ANY", "10.0.0.5", 53, "UDP", "ALLOW", "Allow_DNS_Query"),
        ]
        self.logs = []
        self.alerts = []
        self.ip_request_counter = defaultdict(int)
        self.dos_threshold = 4  # Max packets allowed from one IP in a short burst
        self.stats = {"Total": 0, "Allowed": 0, "Blocked": 0, "Alerts": 0}

    def add_rule(self, src_ip, dst_ip, port, protocol, action, rule_name):
        self.rules.insert(0, (src_ip, dst_ip, port, protocol.upper(), action.upper(), rule_name))
        print(f"[ADMIN] Rule Added: {rule_name} ({action.upper()} {protocol.upper()} Port {port})")

    def check_suspicious_activity(self, src_ip, port):
        self.ip_request_counter[src_ip] += 1
        if self.ip_request_counter[src_ip] > self.dos_threshold:
            alert_msg = f"SECURITY ALERT: Potential DoS/Flooding detected from {src_ip} (Packets: {self.ip_request_counter[src_ip]})"
            if alert_msg not in self.alerts:
                self.alerts.append(alert_msg)
                self.stats["Alerts"] += 1
            return "DoS / High Traffic Flood"
        if port in:
            return "Unauthorized Service Probe"
        return "Normal"

    def inspect_packet(self, packet):
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        port = packet["port"]
        protocol = packet["protocol"]
        traffic_type = packet["traffic_type"]

        self.stats["Total"] += 1
        suspicious_flag = self.check_suspicious_activity(src_ip, port)

        # Auto-block if DoS threshold is exceeded
        if "DoS" in suspicious_flag:
            status = "BLOCKED"
            matched_rule = "Auto_DoS_Mitigation"
        else:
            status = "BLOCKED"  # Default Deny Policy
            matched_rule = "Default_Deny_All"
            for r_src, r_dst, r_port, r_proto, r_action, r_name in self.rules:
                if (r_src == "ANY" or r_src == src_ip) and \
                   (r_dst == "ANY" or r_dst == dst_ip) and \
                   (r_port == "ANY" or r_port == port) and \
                   (r_proto == "ANY" or r_proto == protocol):
                    status = "ALLOWED" if r_action == "ALLOW" else "BLOCKED"
                    matched_rule = r_name
                    break

        if status == "ALLOWED":
            self.stats["Allowed"] += 1
        else:
            self.stats["Blocked"] += 1

        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": port,
            "protocol": protocol,
            "traffic_type": traffic_type,
            "rule": matched_rule,
            "status": status,
            "suspicious": suspicious_flag
        }
        self.logs.append(log_entry)
        self.save_log_to_file(log_entry)

    def save_log_to_file(self, entry):
        with open("firewall_security.log", "a") as f:
            f.write(f"[{entry['timestamp']}] {entry['status']} | {entry['traffic_type']} | "
                    f"{entry['src_ip']} -> {entry['dst_ip']}:{entry['port']} ({entry['protocol']}) | "
                    f"Rule: {entry['rule']} | Activity: {entry['suspicious']}\n")

    def display_dashboard(self):
        print("\n" + "="*95)
        print("                 NETWORK SECURITY & FIREWALL MONITORING DASHBOARD")
        print("="*95)
        print(f"Total Packets: {self.stats['Total']}  |  Allowed: {self.stats['Allowed']}  |  "
              f"Blocked: {self.stats['Blocked']}  |  Security Alerts: {self.stats['Alerts']}")
        print("-"*95)
        print(f"{'Source IP':<15} {'Dest IP':<12} {'Port':<6} {'Proto':<6} {'Type':<9} {'Status':<9} {'Firewall Rule':<22} {'Suspicious Activity'}")
        print("-"*95)
        for log in self.logs:
            print(f"{log['src_ip']:<15} {log['dst_ip']:<12} {log['port']:<6} {log['protocol']:<6} "
                  f"{log['traffic_type']:<9} {log['status']:<9} {log['rule']:<22} {log['suspicious']}")
        
        print("\n" + "="*95)
        print("ACTIVE SECURITY ALERTS:")
        if self.alerts:
            for alert in self.alerts:
                print(f" [!] {alert}")
        else:
            print(" No critical alerts triggered.")
        print("="*95)


# --- Simulation Execution ---
if __name__ == "__main__":
    fw = FirewallMonitoringSystem()

    # Administrator adds a custom rule
    fw.add_rule("192.168.1.10", "10.0.0.5", 22, "TCP", "ALLOW", "Allow_Admin_SSH")

    # Simulated incoming and outgoing network traffic
    sample_traffic = [
        {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.5", "port": 22, "protocol": "TCP", "traffic_type": "Incoming"},
        {"src_ip": "203.0.113.45", "dst_ip": "10.0.0.5", "port": 22, "protocol": "TCP", "traffic_type": "Incoming"},
        {"src_ip": "198.51.100.12", "dst_ip": "10.0.0.5", "port": 443, "protocol": "TCP", "traffic_type": "Incoming"},
        {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "port": 53, "protocol": "UDP", "traffic_type": "Outgoing"},
        {"src_ip": "192.168.1.50", "dst_ip": "10.0.0.5", "port": 80, "protocol": "TCP", "traffic_type": "Incoming"},
        {"src_ip": "172.16.0.99", "dst_ip": "10.0.0.5", "port": 23, "protocol": "TCP", "traffic_type": "Incoming"},
        # Simulated DoS Flood from 45.33.22.11
        {"src_ip": "45.33.22.11", "dst_ip": "10.0.0.5", "port": 80, "protocol": "TCP", "traffic_type": "Incoming"},
        {"src_ip": "45.33.22.11", "dst_ip": "10.0.0.5", "port": 80, "protocol": "TCP", "traffic_type": "Incoming"},
        {"src_ip": "45.33.22.11", "dst_ip": "10.0.0.5", "port": 80, "protocol": "TCP", "traffic_type": "Incoming"},
        {"src_ip": "45.33.22.11", "dst_ip": "10.0.0.5", "port": 80, "protocol": "TCP", "traffic_type": "Incoming"},
        {"src_ip": "45.33.22.11", "dst_ip": "10.0.0.5", "port": 80, "protocol": "TCP", "traffic_type": "Incoming"},
    ]

    for pkt in sample_traffic:
        fw.inspect_packet(pkt)

    fw.display_dashboard()
