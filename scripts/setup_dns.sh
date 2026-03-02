#!/bin/bash
# GoodbyeDPI-Linux: Configure system DNS to bypass ISP DNS poisoning
#
# Usage: sudo bash setup_dns.sh [yandex|cloudflare]
# Default: yandex

set -e

DNS_PROVIDER="${1:-yandex}"

case "$DNS_PROVIDER" in
    yandex)
        DNS1="77.88.8.8"
        DNS2="77.88.8.1"
        DNS6_1="2a02:6b8::feed:0ff"
        DNS6_2="2a02:6b8:0:1::feed:0ff"
        ;;
    cloudflare)
        DNS1="1.1.1.1"
        DNS2="1.0.0.1"
        DNS6_1="2606:4700:4700::1111"
        DNS6_2="2606:4700:4700::1001"
        ;;
    *)
        echo "Usage: sudo bash setup_dns.sh [yandex|cloudflare]"
        exit 1
        ;;
esac

echo "Setting up DNS to $DNS_PROVIDER ($DNS1, $DNS2)..."

IFACE=$(ip route show default | awk '/default/ {print $5}' | head -1)

# Method 1: systemd-resolved
if command -v resolvectl &>/dev/null; then
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/goodbyedpi-linux.conf <<EOF
[Resolve]
DNS=$DNS1 $DNS2 $DNS6_1 $DNS6_2
FallbackDNS=
DNSOverTLS=no
DNSSEC=no
Domains=~.
EOF

    systemctl daemon-reload
    systemctl restart systemd-resolved

    if [ -n "$IFACE" ]; then
        resolvectl dns "$IFACE" "$DNS1" "$DNS2" 2>/dev/null || true
        resolvectl domain "$IFACE" "~." 2>/dev/null || true
    fi

    resolvectl flush-caches 2>/dev/null || true
    systemd-resolve --flush-caches 2>/dev/null || true

# Method 2: Direct /etc/resolv.conf
else
    if [ ! -f /etc/resolv.conf.bak.goodbyedpi ]; then
        cp /etc/resolv.conf /etc/resolv.conf.bak.goodbyedpi
    fi

    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf <<EOF
# GoodbyeDPI-Linux DNS configuration
nameserver $DNS1
nameserver $DNS2
EOF
fi

echo "DNS configured successfully!"
echo "To revert, run: sudo bash remove_dns.sh"
