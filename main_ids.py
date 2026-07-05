import requests
import scapy.all as scapy
import sys
import time

# Telegram configuration
TELEGRAM_TOKEN = "______"
CHAT_ID = "________"

# Global counters
arp_counters = {}
dns_suspicious = {}
http_incomplete = {}

# Thresholds
ARP_THRESHOLD = 5
DOS_THRESHOLD = 10
DNS_LIMIT = 45
ALERT_COOLDOWN = 10

def send_telegram_alert(message):
    """Send alert to Telegram"""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": f"🚨 [IDS ALERT] 🚨\n{message}",
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload, timeout=3)
        print("[+] Alert sent to Telegram!")
    except Exception as e:
        print(f"[-] Telegram Alert Failed: {e}")

def analyze_l2_arp_mdns(pkt, current_time):
    """Detect ARP scanning and mDNS spoofing"""
    global arp_counters
    
    # ARP scanning
    if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op == 1:
        src_mac = pkt[scapy.ARP].hwsrc
        src_ip = pkt[scapy.ARP].psrc if pkt.haslayer(scapy.ARP) else "Unknown"
        if src_mac not in arp_counters:
            arp_counters[src_mac] = {"count": 0, "last_seen": current_time}
        arp_counters[src_mac]["count"] += 1
        arp_counters[src_mac]["last_seen"] = current_time
        if arp_counters[src_mac]["count"] >= ARP_THRESHOLD:
            return f"Stealthy ARP scanning detected!\n-> Attacker IP: {src_ip}\n-> Total requests: {arp_counters[src_mac]['count']}"

    # mDNS spoofing
    if pkt.haslayer(scapy.UDP) and (pkt[scapy.UDP].dport == 5353 or pkt[scapy.UDP].sport == 5353):
        if pkt.haslayer(scapy.DNS) and pkt[scapy.DNS].qr == 1:
            src_ip = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else "Unknown"
            return f"mDNS spoofing detected!\n-> Attacker IP: {src_ip}\n-> Targeted port: 5353"
    return None

def analyze_http_slowloris(pkt, current_time):
    """Detect HTTP Slowloris (incomplete HTTP headers)"""
    if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.Raw):
        src_ip = pkt[scapy.IP].src
        dst_ip = pkt[scapy.IP].dst
        dst_port = pkt[scapy.TCP].dport

        # Only monitor web ports
        if dst_port in [80, 443]:
            try:
                payload = pkt[scapy.Raw].load.decode(errors="ignore")

                # Look for HTTP methods
                if "GET" in payload or "POST" in payload or "HEAD" in payload:
                    # Check if headers are incomplete (no \r\n\r\n terminator)
                    if not payload.endswith("\r\n\r\n"):
                        if src_ip not in http_incomplete:
                            http_incomplete[src_ip] = {"count":0, "last_alert":0}
                        http_incomplete[src_ip]["count"] += 1

                        # Threshold logic
                        if http_incomplete[src_ip]["count"] > DOS_THRESHOLD:
                            if current_time - http_incomplete[src_ip]["last_alert"] > ALERT_COOLDOWN:
                                http_incomplete[src_ip]["last_alert"] = current_time
                                return (f"HTTP Slowloris attack detected!\n"
                                        f"-> Attacker IP: {src_ip}\n"
                                        f"-> Victim IP: {dst_ip}\n"
                                        f"-> Incomplete requests: {http_incomplete[src_ip]['count']}")
            except Exception as e:
                print(f"[-] Error parsing HTTP payload: {e}")
    return None

def analyze_dns_tunneling(pkt, current_time):
    """Detect DNS tunneling by query length"""
    global dns_suspicious
    if pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.DNSQR):
        src_ip = pkt[scapy.IP].src
        try:
            query_name = pkt[scapy.DNSQR].qname
            if isinstance(query_name, bytes):
                query_name = query_name.decode('utf-8', errors='ignore')
            query_name = query_name.rstrip('.')
            if len(query_name) > DNS_LIMIT:
                if src_ip not in dns_suspicious:
                    dns_suspicious[src_ip] = {"last_alert": 0}
                if current_time - dns_suspicious[src_ip]["last_alert"] > ALERT_COOLDOWN:
                    dns_suspicious[src_ip]["last_alert"] = current_time
                    return f"Potential DNS tunneling detected!\n-> Source IP: {src_ip}\n-> Long query ({len(query_name)} chars): {query_name}"
        except Exception:
            pass
    return None

def check_honeypot_trap(pkt):
    """Detect probes to honeypot ports (FTP/Telnet)"""
    if pkt.haslayer(scapy.TCP) and pkt.haslayer(scapy.IP):
        dest_port = pkt[scapy.TCP].dport
        if dest_port in [21, 23]:
            src_ip = pkt[scapy.IP].src
            return f"Honeypot triggered! Scanner probing decoy port!\n-> Attacker IP: {src_ip}\n-> Targeted port: {dest_port}"
    return None

def packet_callback(packet):
    current_time = time.time()
    try:
        # Honeypot check first
        alert = (
            check_honeypot_trap(packet) or
            analyze_l2_arp_mdns(packet, current_time) or 
            analyze_http_slowloris(packet, current_time) or 
            analyze_dns_tunneling(packet, current_time)
        )
        if alert:
            print(f"[DETECTED] {alert.splitlines()[0]}")
            send_telegram_alert(alert)
    except Exception as e:
        print(f"[-] Error parsing packet: {e}")

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else "enp0s8"
    print("=======================================")
    print(f"[*] IDS listening on: {iface}")
    print("[*] Status: Ready. Press Ctrl+C to stop.")
    print("=======================================")
    try:
        scapy.sniff(iface=iface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[+] IDS stopped.")

if __name__ == "__main__":
    main()





