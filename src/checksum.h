#ifndef _CHECKSUM_H
#define _CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

/* Calculate IPv4 header checksum */
uint16_t ip_checksum(const void *buf, size_t len);

/* Calculate TCP checksum with IPv4 pseudo-header */
uint16_t tcp4_checksum(const void *ip_hdr, const void *tcp_pkt, size_t tcp_len);

/* Calculate TCP checksum with IPv6 pseudo-header */
uint16_t tcp6_checksum(const void *ip6_hdr, const void *tcp_pkt, size_t tcp_len);

/* Calculate UDP checksum with IPv4 pseudo-header */
uint16_t udp4_checksum(const void *ip_hdr, const void *udp_pkt, size_t udp_len);

/* Calculate UDP checksum with IPv6 pseudo-header */
uint16_t udp6_checksum(const void *ip6_hdr, const void *udp_pkt, size_t udp_len);

/* Recalculate all checksums for a full packet (IPv4 or IPv6, TCP or UDP) */
void recalc_checksums(char *packet, size_t packet_len);

#endif /* _CHECKSUM_H */
