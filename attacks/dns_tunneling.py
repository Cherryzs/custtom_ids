import os
import time

def simulate_dns_tunneling():
    print("[*] Launching simulated DNS tunneling attack...")

    payloads = [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.example.com",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.example.com",
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff.example.com"
    ]

    for payload in payloads:
        print(f"[+] Sending suspicious query: {payload}")
        # Hantar ke IDS Ubuntu IP (Host-Only interface)
        os.system(f"dig {payload} @192.168.56.104")
        time.sleep(1)

if __name__ == "__main__":
    simulate_dns_tunneling()
