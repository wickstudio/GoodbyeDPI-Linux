#!/bin/bash
# GoodbyeDPI-Linux: Remove custom DNS configuration
#
# Usage: sudo bash remove_dns.sh

set -e

echo "Removing custom DNS configuration..."

# Method 1: systemd-resolved
if [ -f /etc/systemd/resolved.conf.d/goodbyedpi-linux.conf ]; then
    rm -f /etc/systemd/resolved.conf.d/goodbyedpi-linux.conf
    systemctl restart systemd-resolved
fi

# Method 2: Direct /etc/resolv.conf
if [ -f /etc/resolv.conf.bak.goodbyedpi ]; then
    cp /etc/resolv.conf.bak.goodbyedpi /etc/resolv.conf
    rm -f /etc/resolv.conf.bak.goodbyedpi
fi

echo "DNS configuration reverted to system defaults."