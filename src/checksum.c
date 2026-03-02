/*
 * IP/TCP/UDP Checksum Calculation for GoodbyeDPI-Linux
 *
 * Replaces WinDivertHelperCalcChecksums from the Windows version.
 * Implements standard RFC 1071 checksum algorithm for:
 *   - IPv4 header checksum
 *   - TCP checksum (with IPv4 and IPv6 pseudo-headers)
 *   - UDP checksum (with IPv4 and IPv6 pseudo-headers)
 */

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "checksum.h"

/**
 * Generic checksum calculation using RFC 1071 algorithm
 * Computes the one's complement sum of 16-bit words
 */
static uint32_t checksum_add(const void *buf, size_t len) {
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)buf;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    /* Handle odd byte */
    if (len == 1) {
        uint16_t last = 0;
        *(uint8_t *)&last = *(const uint8_t *)ptr;
        sum += last;
    }

    return sum;
}

/**
 * Fold 32-bit sum into 16-bit checksum
 */
static uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

/**
 * Calculate IPv4 header checksum
 */
uint16_t ip_checksum(const void *buf, size_t len) {
    return checksum_finish(checksum_add(buf, len));
}

/**
 * Calculate TCP checksum with IPv4 pseudo-header
 */
uint16_t tcp4_checksum(const void *ip_hdr, const void *tcp_pkt, size_t tcp_len) {
    const struct iphdr *iph = (const struct iphdr *)ip_hdr;
    uint32_t sum = 0;

    /* IPv4 pseudo-header */
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons((uint16_t)tcp_len);

    /* TCP segment */
    sum += checksum_add(tcp_pkt, tcp_len);

    return checksum_finish(sum);
}

/**
 * Calculate TCP checksum with IPv6 pseudo-header
 */
uint16_t tcp6_checksum(const void *ip6_hdr, const void *tcp_pkt, size_t tcp_len) {
    const struct ip6_hdr *ip6h = (const struct ip6_hdr *)ip6_hdr;
    uint32_t sum = 0;

    /* IPv6 pseudo-header */
    sum += checksum_add(&ip6h->ip6_src, 16);
    sum += checksum_add(&ip6h->ip6_dst, 16);
    sum += htons((uint16_t)tcp_len);
    sum += htons(IPPROTO_TCP);

    /* TCP segment */
    sum += checksum_add(tcp_pkt, tcp_len);

    return checksum_finish(sum);
}

/**
 * Calculate UDP checksum with IPv4 pseudo-header
 */
uint16_t udp4_checksum(const void *ip_hdr, const void *udp_pkt, size_t udp_len) {
    const struct iphdr *iph = (const struct iphdr *)ip_hdr;
    uint32_t sum = 0;

    /* IPv4 pseudo-header */
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += htons((uint16_t)udp_len);

    /* UDP datagram */
    sum += checksum_add(udp_pkt, udp_len);

    return checksum_finish(sum);
}

/**
 * Calculate UDP checksum with IPv6 pseudo-header
 */
uint16_t udp6_checksum(const void *ip6_hdr, const void *udp_pkt, size_t udp_len) {
    const struct ip6_hdr *ip6h = (const struct ip6_hdr *)ip6_hdr;
    uint32_t sum = 0;

    /* IPv6 pseudo-header */
    sum += checksum_add(&ip6h->ip6_src, 16);
    sum += checksum_add(&ip6h->ip6_dst, 16);
    sum += htons((uint16_t)udp_len);
    sum += htons(IPPROTO_UDP);

    /* UDP datagram */
    sum += checksum_add(udp_pkt, udp_len);

    return checksum_finish(sum);
}

/**
 * Recalculate all checksums for a full packet.
 * Detects IPv4/IPv6, TCP/UDP and recalculates appropriately.
 */
void recalc_checksums(char *packet, size_t packet_len) {
    /* Check IP version from the first nibble */
    uint8_t version = (*(uint8_t *)packet) >> 4;

    if (version == 4) {
        struct iphdr *iph = (struct iphdr *)packet;
        size_t ip_hdr_len = (size_t)iph->ihl * 4;

        if (packet_len < ip_hdr_len)
            return;

        /* Recalculate IPv4 header checksum */
        iph->check = 0;
        iph->check = ip_checksum(iph, ip_hdr_len);

        char *transport = packet + ip_hdr_len;
        size_t transport_len = packet_len - ip_hdr_len;

        if (iph->protocol == IPPROTO_TCP && transport_len >= sizeof(struct tcphdr)) {
            struct tcphdr *tcph = (struct tcphdr *)transport;
            tcph->check = 0;
            tcph->check = tcp4_checksum(iph, tcph, transport_len);
        }
        else if (iph->protocol == IPPROTO_UDP && transport_len >= sizeof(struct udphdr)) {
            struct udphdr *udph = (struct udphdr *)transport;
            udph->check = 0;
            udph->check = udp4_checksum(iph, udph, transport_len);
            if (udph->check == 0)
                udph->check = 0xFFFF;
        }
    }
    else if (version == 6) {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)packet;
        size_t ip6_hdr_len = sizeof(struct ip6_hdr);

        if (packet_len < ip6_hdr_len)
            return;

        char *transport = packet + ip6_hdr_len;
        size_t transport_len = packet_len - ip6_hdr_len;
        uint8_t next_header = ip6h->ip6_nxt;

        if (next_header == IPPROTO_TCP && transport_len >= sizeof(struct tcphdr)) {
            struct tcphdr *tcph = (struct tcphdr *)transport;
            tcph->check = 0;
            tcph->check = tcp6_checksum(ip6h, tcph, transport_len);
        }
        else if (next_header == IPPROTO_UDP && transport_len >= sizeof(struct udphdr)) {
            struct udphdr *udph = (struct udphdr *)transport;
            udph->check = 0;
            udph->check = udp6_checksum(ip6h, udph, transport_len);
            if (udph->check == 0)
                udph->check = 0xFFFF;
        }
    }
}
