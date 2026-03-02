#!/bin/bash
# GoodbyeDPI-Linux: Universal Setup & Manager Script
# https://github.com/wickstudio | discord.gg/wicks

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[✗] Please run as root: sudo bash ./goodbyedpi-manager.sh${NC}"
    exit 1
fi

check_dns() {
    if [ -f /etc/systemd/resolved.conf.d/goodbyedpi-linux.conf ] || [ -f /etc/resolv.conf.bak.goodbyedpi ]; then
        echo -e "${GREEN}[✔]${NC}"
    else
        echo -e "${YELLOW}[ ]${NC}"
    fi
}

check_compiled() {
    if [ -f "src/goodbyedpi" ]; then
        echo -e "${GREEN}[✔]${NC}"
    else
        echo -e "${YELLOW}[ ]${NC}"
    fi
}

check_service() {
    if systemctl is-enabled goodbyedpi.service &>/dev/null; then
        echo -e "${GREEN}[✔]${NC}"
    else
        echo -e "${YELLOW}[ ]${NC}"
    fi
}

while true; do
    echo -e "\n${BLUE}=======================================${NC}"
    echo -e "${GREEN}      GoodbyeDPI-Linux Manager         ${NC}"
    echo -e "${BLUE}=======================================${NC}"

    echo -e "Select an option:"
    echo -e "$(check_compiled) 1) Install Dependencies & Compile (First Time Setup)"
    echo -e "$(check_dns) 2) Configure DNS Poisoning Bypass (Yandex/Cloudflare)"
    echo -e "$(check_service) 3) Install as Auto-Start Service (Runs on boot)"
    echo -e "    4) Remove Auto-Start Service"
    echo -e "    5) Start GoodbyeDPI Temporarily (In this window)"
    echo -e "    6) Stop All & Remove Rules"
    echo -e "    0) Exit"
    echo -e "${BLUE}=======================================${NC}"
    read -p "Enter choice [0-6]: " choice

    case $choice in
        1)
            echo -e "\n${BLUE}[*] Detecting Operating System...${NC}"
            if [ -f /etc/debian_version ]; then
                echo -e "${GREEN}[✔] Debian/Ubuntu detected.${NC}"
                apt update && apt install -y build-essential libnetfilter-queue-dev iptables dnsutils
            elif [ -f /etc/arch-release ]; then
                echo -e "${GREEN}[✔] Arch Linux detected.${NC}"
                pacman -Sy --noconfirm base-devel libnetfilter_queue iptables bind
            elif [ -f /etc/fedora-release ]; then
                echo -e "${GREEN}[✔] Fedora detected.${NC}"
                dnf groupinstall -y "Development Tools"
                dnf install -y libnetfilter_queue-devel iptables bind-utils
            else
                echo -e "${RED}[!] Unsupported OS. Please install 'make', 'gcc', 'iptables', and 'libnetfilter-queue' manually.${NC}"
            fi
            
            echo -e "\n${BLUE}[*] Compiling GoodbyeDPI-Linux...${NC}"
            cd src && make clean && make && cd ..
            echo -e "${GREEN}[✔] Compilation complete!${NC}"
            
            echo -e "\nPress Enter to return to menu..."
            read
            ;;
            
        2)
            echo -e "\n${BLUE}[*] Setting up DNS Bypass...${NC}"
            bash scripts/setup_dns.sh yandex
            echo -e "${GREEN}[✔] DNS setup complete.${NC}"
            
            echo -e "\nPress Enter to return to menu..."
            read
            ;;
            
        3)
            if [ ! -f "src/goodbyedpi" ]; then
                echo -e "${RED}[✗] goodbyedpi executable not found! Please run Option 1 first.${NC}"
                sleep 2
                continue
            fi
            echo -e "\n${BLUE}[*] Installing GoodbyeDPI-Linux systemd service...${NC}"
            
            DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
            
            cat > /etc/systemd/system/goodbyedpi.service <<EOF
[Unit]
Description=GoodbyeDPI-Linux Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=${DIR}/scripts/setup_iptables.sh
ExecStart=${DIR}/src/goodbyedpi
ExecStopPost=${DIR}/scripts/remove_iptables.sh
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF
            
            systemctl daemon-reload
            systemctl enable goodbyedpi
            systemctl start goodbyedpi
            
            echo -e "${GREEN}[✔] Setup complete! GoodbyeDPI is now running in the background and will start on boot.${NC}"
            echo -e "Use ${YELLOW}systemctl status goodbyedpi${NC} to check status."
            
            echo -e "\nPress Enter to return to menu..."
            read
            ;;
            
        4)
            echo -e "\n${BLUE}[*] Removing GoodbyeDPI-Linux service...${NC}"
            systemctl stop goodbyedpi 2>/dev/null || true
            systemctl disable goodbyedpi 2>/dev/null || true
            rm -f /etc/systemd/system/goodbyedpi.service
            systemctl daemon-reload
            bash scripts/remove_iptables.sh || true
            echo -e "${GREEN}[✔] Auto-start service removed successfully.${NC}"
            
            echo -e "\nPress Enter to return to menu..."
            read
            ;;
            
        5)
            if [ ! -f "src/goodbyedpi" ]; then
                echo -e "${RED}[✗] goodbyedpi executable not found! Please run Option 1 first.${NC}"
                sleep 2
                continue
            fi
            
            if systemctl is-active goodbyedpi.service &>/dev/null; then
                echo -e "${RED}[!] The GoodByeDPI auto-start service is currently running.${NC}"
                echo -e "Please stop/remove it (Option 4) before running temporarily."
                sleep 3
                continue
            fi

            echo -e "\n${BLUE}[*] Setting up iptables rules...${NC}"
            bash scripts/setup_iptables.sh
            echo -e "\n${BLUE}[*] Starting GoodbyeDPI-Linux... (Press Ctrl+C to stop and return to menu)${NC}"
            
            (
                trap "bash scripts/remove_iptables.sh; exit 0" SIGINT SIGTERM
                ./src/goodbyedpi
            )
            
            echo -e "\n${GREEN}[✔] GoodbyeDPI stopped.${NC}"
            
            echo -e "\nPress Enter to return to menu..."
            read
            ;;
            
        6)
            echo -e "\n${BLUE}[*] Stopping GoodbyeDPI & Restoring rules...${NC}"
            systemctl stop goodbyedpi 2>/dev/null || true
            killall goodbyedpi 2>/dev/null || true
            bash scripts/remove_iptables.sh
            bash scripts/remove_dns.sh
            echo -e "${GREEN}[✔] All rules and background processes removed.${NC}"
            
            echo -e "\nPress Enter to return to menu..."
            read
            ;;
            
        0)
            echo -e "${GREEN}Goodbye!${NC}"
            exit 0
            ;;
            
        *)
            echo -e "${RED}Invalid option! Try again.${NC}"
            sleep 1
            ;;
    esac
done