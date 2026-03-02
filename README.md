# GoodbyeDPI-Linux

![GoodbyeDPI](https://img.shields.io/badge/GoodbyeDPI-Linux-blue?style=for-the-badge&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

A powerful, highly optimized Linux port of [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) using `NFQUEUE` to seamlessly bypass Deep Packet Inspection (DPI) and DNS poisoning used by ISPs worldwide.

Whether it's **Discord, YouTube, Twitter**, or any other blocked service, GoodbyeDPI-Linux operates stealthily at the packet level to restore your internet freedom without needing a VPN.

---

## Connect With Us
- **Github:** [github.com/wickstudio](https://github.com/wickstudio)
- **Developer:** [Instagram - wicknux](https://www.instagram.com/wicknux/)
- **Discord Community:** [discord.gg/wicks](https://discord.gg/wicks)

---

## How It Works

ISPs use DPI to analyze your traffic and drop connections to blocked sites. GoodbyeDPI-Linux defeats this using active circumvention:
1. **HTTPS/HTTP Fragmentation:** Splits the initial request so DPI hardware can't read the SNI or Host header.
2. **Fake Packets (TTL-Limited):** Floods the ISP's DPI boxes with fake packets that have a low Time-To-Live (TTL). The DPI gets confused and allows the real connection, but the fake packets expire before reaching the actual server.
3. **TCP Checksum/Sequence alterations:** Sends invalid packets that trick DPI systems but are safely ignored by destination servers.
4. **QUIC Blocking:** Forces browsers to fall back to standard TCP/HTTPS, which is much easier to unblock.

## Installation

```bash
git clone https://github.com/wickstudio/GoodbyeDPI-Linux.git
cd GoodbyeDPI-Linux
```

---

## Usage Guide

We have created an interactive manager to handle EVERYTHING for you (dependencies, compilation, DNS, and auto-start services).

Run the interactive manager as root:
```bash
sudo ./goodbyedpi-manager.sh
```

### Menu Options:
1. **Install Dependencies & Compile:** Automatically installs required packages (Ubuntu/Debian, Arch, Fedora supported) and builds the project.
2. **Install as Auto-Start Service:** Sets up systemd so GoodbyeDPI runs automatically in the background every time you boot your computer.
3. **Remove Auto-Start Service:** Safely uninstalls the background service.
4. **Configure DNS Poisoning Bypass:** ISPs often hijack DNS requests to block sites like Discord. Run this once to configure your system to use an encrypted DNS provider (Yandex).
5. **Start GoodbyeDPI Temporarily:** Runs GoodbyeDPI in the current terminal window (closes when you press `Ctrl+C`).
6. **Stop All & Remove Rules:** Stops the service and flushes all iptables rules, restoring your normal network connection.

---

## Troubleshooting

- **Discord/Sites still blocked?** Ensure you ran Option `4` (DNS Bypass) in the manager. DNS poisoning is the #1 reason sites remain blocked. Check your DNS with `dig discord.com` (it should return a real IP, not an ISP block page).
- **Internet completely down?** Run Option `6` in the manager to restore your standard network configuration.

## Credits
- Based on the legendary [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) by ValdikSS.
- Linux NFQUEUE port by original authors.
- Aggressive bypass configurations inspired by the community.
