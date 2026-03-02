#!/bin/bash
# GoodbyeDPI-Linux: Setup iptables rules for NFQUEUE packet interception
# Run this script with: sudo bash setup_iptables.sh

set -e

QUEUE_NUM=200
MARK=0x10

echo "Setting up iptables rules for GoodbyeDPI-Linux (queue $QUEUE_NUM)..."

# Skip packets injected by goodbyedpi (marked with fwmark)
iptables -t mangle -A OUTPUT -m mark --mark $MARK -j ACCEPT
iptables -t mangle -A INPUT -m mark --mark $MARK -j ACCEPT

# Outbound TCP to port 80 (HTTP) - exclude loopback
iptables -t mangle -A OUTPUT ! -o lo -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass
# Outbound TCP to port 443 (HTTPS) - exclude loopback
iptables -t mangle -A OUTPUT ! -o lo -p tcp --dport 443 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass

# Inbound TCP from port 80 (HTTP responses)
iptables -t mangle -A INPUT ! -i lo -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass
# Inbound TCP from port 443 (HTTPS responses / SYN-ACK)
iptables -t mangle -A INPUT ! -i lo -p tcp --sport 443 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass

# IPv6 rules (optional)
ip6tables -t mangle -A OUTPUT -m mark --mark $MARK -j ACCEPT 2>/dev/null || true
ip6tables -t mangle -A INPUT -m mark --mark $MARK -j ACCEPT 2>/dev/null || true
ip6tables -t mangle -A OUTPUT ! -o lo -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
ip6tables -t mangle -A OUTPUT ! -o lo -p tcp --dport 443 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
ip6tables -t mangle -A INPUT ! -i lo -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
ip6tables -t mangle -A INPUT ! -i lo -p tcp --sport 443 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true

echo "iptables rules set up successfully!"
echo "You can now run: sudo ./goodbyedpi"
