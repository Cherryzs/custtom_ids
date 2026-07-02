# custtom_ids

```markdown
# Custom IDS/IPS Project

## Project Overview
This project implements a custom Intrusion Detection System (IDS) in Python using Scapy.  
The IDS is capable of detecting five attack types:
- Stealthy ARP Scanning
- mDNS Spoofing
- HTTP Slowloris
- DNS Tunneling
- Honeypot Probes (FTP/Telnet)

Alerts are generated in real time and sent to a Telegram bot for notification.

---

## Setup Instructions
1. Install **VirtualBox** and create two VMs:
   - **Ubuntu** → runs the IDS (victim/target machine).
   - **Kali Linux** → used to simulate attacks (attacker machine).
2. Configure networking:
   - **Host‑Only Adapter** → for internal traffic monitoring.
   - **NAT Adapter** → for internet access (Telegram alerts).
3. Install required tools:
   - Python 3
   - Scapy
   - Requests library
   - Wireshark (for traffic verification)

---

## How to Run IDS
On the Ubuntu VM:
```bash
sudo python3 ids.py
```
By default, the IDS listens on interface `enp0s8`. You can specify another interface:
```bash
sudo python3 ids.py <interface_name>
```

---

## Example Attacks
Run these commands on the Kali Linux VM to trigger alerts:

- **ARP Scan:**  
  ```bash
  arp-scan -I eth0 192.168.56.0/24
  ```

- **mDNS Spoofing:**  
  ```bash
  python3 mdns_spoof.py
  ```

- **Slowloris Attack:**  
  ```bash
  slowloris -s 20 -v <target_ip>
  ```

- **DNS Tunneling:**  
  ```bash
  iodine -f -P password <target_ip>
  ```

- **Honeypot Probe:**  
  ```bash
  nmap -p 21,23 <target_ip>
  ```

---

## Expected Alerts
When attacks are detected, alerts appear in:
- IDS terminal output  
- Telegram bot messages  

**Example alert screenshots will be placed here.**

---

## Telegram Setup
1. Create a bot using **BotFather** in Telegram.  
2. Obtain the **API token** and **chat ID**.  
3. Update the following variables in `ids.py`:
   ```python
   TELEGRAM_TOKEN = "your_bot_token"
   CHAT_ID = "your_chat_id"
   ```

---

## Team Members
- Rabiatul  
- Huwaina
- A'ilia
- Najihah


---

