#!/bin/bash
# GoodbyeDPI-Linux: Remove iptables rules
# Run this script with: sudo bash remove_iptables.sh

set -e

QUEUE_NUM=200
MARK=0x10

echo "Removing iptables rules for GoodbyeDPI-Linux (queue $QUEUE_NUM)..."

# Remove all possible rule variants (current + old formats)
for TBL in iptables ip6tables; do
    $TBL -t mangle -D OUTPUT -m mark --mark $MARK -j ACCEPT 2>/dev/null || true
    $TBL -t mangle -D INPUT -m mark --mark $MARK -j ACCEPT 2>/dev/null || true
    # Current format (with loopback exclusion)
    $TBL -t mangle -D OUTPUT ! -o lo -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D OUTPUT ! -o lo -p tcp --dport 443 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D INPUT ! -i lo -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D INPUT ! -i lo -p tcp --sport 443 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    # Old format (without loopback exclusion)
    $TBL -t mangle -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D INPUT -p tcp --sport 80 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D INPUT -p tcp --sport 443 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    # Old DNS rules
    $TBL -t mangle -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D OUTPUT ! -o lo -p udp --dport 53 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D INPUT ! -i lo -p udp --sport 53 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    $TBL -t mangle -D INPUT ! -i lo -p udp --sport 1253 -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass 2>/dev/null || true
    # Old conntrack rules
    $TBL -t raw -D OUTPUT ! -o lo -p udp --dport 53 -j CT --notrack 2>/dev/null || true
    $TBL -t raw -D PREROUTING -p udp --sport 1253 -j CT --notrack 2>/dev/null || true
    $TBL -t raw -D PREROUTING -p udp --sport 53 -j CT --notrack 2>/dev/null || true
done

echo "iptables rules removed successfully!"
