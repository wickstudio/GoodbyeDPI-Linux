/*
 * GoodbyeDPI-Linux — Passive DPI blocker and Active DPI circumvention utility.
 * Linux port using NFQUEUE (libnetfilter_queue) instead of WinDivert.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "goodbyedpi.h"
#include "utils/repl_str.h"
#include "service.h"
#include "dnsredir.h"
#include "ttltrack.h"
#include "blackwhitelist.h"
#include "fakepackets.h"
#include "nfqueue.h"
#include "checksum.h"

#define GOODBYEDPI_VERSION "v0.2.3rc3-linux"
#define die() do { sleep(20); exit(EXIT_FAILURE); } while (0)

static int exiting = 0;
static nfqueue_handle_t *nfq_handles[4] = {NULL};
static int nfq_handle_count = 0;

static const char http10_redirect_302[] = "HTTP/1.0 302 ";
static const char http11_redirect_302[] = "HTTP/1.1 302 ";
static const char http_host_find[] = "\r\nHost: ";
static const char http_host_replace[] = "\r\nhoSt: ";
static const char http_useragent_find[] = "\r\nUser-Agent: ";
static const char location_http[] = "\r\nLocation: http://";
static const char connection_close[] = "\r\nConnection: close";
static const char *http_methods[] = {
    "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ",
};

/* Global configuration flags */
static int do_passivedpi = 0, do_block_quic = 0,
    do_fragment_http = 0,
    do_fragment_http_persistent = 0,
    do_fragment_http_persistent_nowait = 0,
    do_fragment_https = 0, do_host = 0,
    do_host_removespace = 0, do_additional_space = 0,
    do_http_allports = 0,
    do_host_mixedcase = 0,
    do_dnsv4_redirect = 0, do_dnsv6_redirect = 0,
    do_dns_verb = 0, do_tcp_verb = 0, do_blacklist = 0,
    do_allow_no_sni = 0,
    do_fragment_by_sni = 0,
    do_fake_packet = 0,
    do_auto_ttl = 0,
    do_wrong_chksum = 0,
    do_wrong_seq = 0,
    do_native_frag = 0, do_reverse_frag = 0;
static unsigned int http_fragment_size = 0;
static unsigned int https_fragment_size = 0;
static unsigned short max_payload_size = 0;
static uint8_t ttl_of_fake_packet = 0;
static uint8_t ttl_min_nhops = 0;
static uint8_t auto_ttl_1 = 0;
static uint8_t auto_ttl_2 = 0;
static uint8_t auto_ttl_max = 0;
static uint32_t dnsv4_addr = 0;
static struct in6_addr dnsv6_addr = {{{0}}};
static uint16_t dnsv4_port = 0;
static uint16_t dnsv6_port = 0;

static struct option long_options[] = {
    {"port",        required_argument, 0,  'z' },
    {"dns-addr",    required_argument, 0,  'd' },
    {"dns-port",    required_argument, 0,  'g' },
    {"dnsv6-addr",  required_argument, 0,  '!' },
    {"dnsv6-port",  required_argument, 0,  '@' },
    {"dns-verb",    no_argument,       0,  'v' },
    {"blacklist",   required_argument, 0,  'b' },
    {"allow-no-sni",no_argument,       0,  ']' },
    {"frag-by-sni", no_argument,       0,  '>' },
    {"ip-id",       required_argument, 0,  'i' },
    {"set-ttl",     required_argument, 0,  '$' },
    {"min-ttl",     required_argument, 0,  '[' },
    {"auto-ttl",    optional_argument, 0,  '+' },
    {"wrong-chksum",no_argument,       0,  '%' },
    {"wrong-seq",   no_argument,       0,  ')' },
    {"native-frag", no_argument,       0,  '*' },
    {"reverse-frag",no_argument,       0,  '(' },
    {"max-payload", optional_argument, 0,  '|' },
    {"fake-from-hex", required_argument, 0,  'u' },
    {"fake-with-sni", required_argument, 0,  '}' },
    {"fake-gen",    required_argument, 0,  'j' },
    {"fake-resend", required_argument, 0,  't' },
    {"debug-exit",  optional_argument, 0,  'x' },
    {"daemon",      no_argument,       0,  'D' },
    {0,             0,                 0,   0  }
};

static char* dumb_memmem(const char* haystack, unsigned int hlen,
                         const char* needle, unsigned int nlen)
{
    if (nlen > hlen) return NULL;
    size_t i;
    for (i=0; i<hlen-nlen+1; i++) {
        if (memcmp(haystack+i,needle,nlen)==0) {
            return (char*)(haystack+i);
        }
    }
    return NULL;
}

static unsigned short int atousi(const char *str, const char *msg) {
    long unsigned int res = strtoul(str, NULL, 10u);
    if(res > 0xFFFFu) { puts(msg); exit(1); }
    return (unsigned short int)res;
}

static uint8_t atoub(const char *str, const char *msg) {
    long unsigned int res = strtoul(str, NULL, 10u);
    if(res > 0xFFu) { puts(msg); exit(1); }
    return (uint8_t)res;
}

void deinit_all(void) {
    for (int i = 0; i < nfq_handle_count; i++) {
        if (nfq_handles[i]) {
            nfqueue_stop(nfq_handles[i]);
            nfqueue_close(nfq_handles[i]);
            nfq_handles[i] = NULL;
        }
    }
    raw_socket_close();
}

static void sigint_handler(int sig __attribute__((unused))) {
    exiting = 1;
    deinit_all();
    exit(EXIT_SUCCESS);
}

static void mix_case(char *pktdata, unsigned int pktlen) {
    unsigned int i;
    if (pktlen <= 0) return;
    for (i = 0; i < pktlen; i++) {
        if (i % 2) pktdata[i] = (char) toupper(pktdata[i]);
    }
}

static int is_passivedpi_redirect(const char *pktdata, unsigned int pktlen) {
    if (memcmp(pktdata, http11_redirect_302, sizeof(http11_redirect_302)-1) == 0 ||
        memcmp(pktdata, http10_redirect_302, sizeof(http10_redirect_302)-1) == 0)
    {
        if (dumb_memmem(pktdata, pktlen, location_http, sizeof(location_http)-1) &&
            dumb_memmem(pktdata, pktlen, connection_close, sizeof(connection_close)-1)) {
            return TRUE;
        }
    }
    return FALSE;
}

static int find_header_and_get_info(const char *pktdata, unsigned int pktlen,
                const char *hdrname,
                char **hdrnameaddr,
                char **hdrvalueaddr, unsigned int *hdrvaluelen) {
    char *data_addr_rn;
    char *hdr_begin;
    *hdrvaluelen = 0u;
    *hdrnameaddr = NULL;
    *hdrvalueaddr = NULL;
    hdr_begin = dumb_memmem(pktdata, pktlen, hdrname, (unsigned int)strlen(hdrname));
    if (!hdr_begin) return FALSE;
    if (pktdata > hdr_begin) return FALSE;
    *hdrnameaddr = hdr_begin;
    *hdrvalueaddr = hdr_begin + strlen(hdrname);
    data_addr_rn = dumb_memmem(*hdrvalueaddr,
                        pktlen - (unsigned int)(*hdrvalueaddr - pktdata), "\r\n", 2);
    if (data_addr_rn) {
        *hdrvaluelen = (unsigned int)(data_addr_rn - *hdrvalueaddr);
        if (*hdrvaluelen >= 3 && *hdrvaluelen <= HOST_MAXLEN)
            return TRUE;
    }
    return FALSE;
}

static int extract_sni(const char *pktdata, unsigned int pktlen,
                    char **hostnameaddr, unsigned int *hostnamelen) {
    unsigned int ptr = 0;
    unsigned const char *d = (unsigned const char *)pktdata;
    unsigned const char *hnaddr = 0;
    int hnlen = 0;
    while (ptr + 8 < pktlen) {
        if (d[ptr] == '\0' && d[ptr+1] == '\0' && d[ptr+2] == '\0' &&
            d[ptr+4] == '\0' && d[ptr+6] == '\0' && d[ptr+7] == '\0' &&
            d[ptr+3] - d[ptr+5] == 2 && d[ptr+5] - d[ptr+8] == 3)
            {
                if (ptr + 8 + d[ptr+8] > pktlen) return FALSE;
                hnaddr = &d[ptr+9];
                hnlen = d[ptr+8];
                if (hnlen < 3 || hnlen > HOST_MAXLEN) return FALSE;
                for (int i=0; i<hnlen; i++) {
                    if (!( (hnaddr[i] >= '0' && hnaddr[i] <= '9') ||
                         (hnaddr[i] >= 'a' && hnaddr[i] <= 'z') ||
                         hnaddr[i] == '.' || hnaddr[i] == '-'))
                        return FALSE;
                }
                *hostnameaddr = (char*)hnaddr;
                *hostnamelen = (unsigned int)hnlen;
                return TRUE;
            }
        ptr++;
    }
    return FALSE;
}

static inline void change_window_size(struct tcphdr *tcph, unsigned int size) {
    if (size >= 1 && size <= 0xFFFFu)
        tcph->window = htons((uint16_t)size);
}

static void* find_http_method_end(const char *pkt, unsigned int http_frag, int *is_fragmented) {
    unsigned int i;
    for (i = 0; i<(sizeof(http_methods) / sizeof(*http_methods)); i++) {
        if (memcmp(pkt, http_methods[i], strlen(http_methods[i])) == 0) {
            if (is_fragmented) *is_fragmented = 0;
            return (char*)pkt + strlen(http_methods[i]) - 1;
        }
        if ((http_frag == 1 || http_frag == 2) &&
            memcmp(pkt, http_methods[i] + http_frag,
                   strlen(http_methods[i]) - http_frag) == 0)
        {
            if (is_fragmented) *is_fragmented = 1;
            return (char*)pkt + strlen(http_methods[i]) - http_frag - 1;
        }
    }
    return NULL;
}

/**
 * Send a native fragment of the packet.
 * step=0: send first fragment_size bytes
 * step=1: send remaining bytes after fragment_size
 */
static void send_native_fragment(unsigned char *packet, unsigned int packetLen,
                        char *packet_data, unsigned int packet_dataLen,
                        int packet_v4, int packet_v6,
                        struct iphdr *ipHdr, struct ip6_hdr *ip6Hdr,
                        struct tcphdr *tcpHdr,
                        unsigned int fragment_size, int step) {
    char packet_bak[MAX_PACKET_SIZE];
    memcpy(packet_bak, packet, packetLen);
    unsigned int orig_packetLen = packetLen;

    if (fragment_size >= packet_dataLen) {
        if (step == 1) fragment_size = 0;
        else return;
    }

    if (step == 0) {
        if (packet_v4)
            ipHdr->tot_len = htons(
                ntohs(ipHdr->tot_len) - packet_dataLen + fragment_size);
        else if (packet_v6)
            ip6Hdr->ip6_plen = htons(
                ntohs(ip6Hdr->ip6_plen) - packet_dataLen + fragment_size);
        packetLen = packetLen - packet_dataLen + fragment_size;
    }
    else if (step == 1) {
        if (packet_v4)
            ipHdr->tot_len = htons(ntohs(ipHdr->tot_len) - fragment_size);
        else if (packet_v6)
            ip6Hdr->ip6_plen = htons(ntohs(ip6Hdr->ip6_plen) - fragment_size);
        memmove(packet_data, packet_data + fragment_size, packet_dataLen - fragment_size);
        packetLen -= fragment_size;
        tcpHdr->seq = htonl(ntohl(tcpHdr->seq) + fragment_size);
    }

    recalc_checksums((char *)packet, packetLen);
    raw_socket_send((const char *)packet, packetLen);
    memcpy(packet, packet_bak, orig_packetLen);
}

/**
 * Main NFQUEUE packet processing callback.
 * This replaces the while(1) { WinDivertRecv... } loop from Windows.
 */
static int packet_callback(int queue_id, unsigned char *packet, size_t packet_len,
                           int is_outbound, void *user_data)
{
    (void)queue_id;
    (void)user_data;

    int should_reinject = 1;
    int should_recalc_checksum = 0;
    int sni_ok = 0;
    int packet_v4 = 0, packet_v6 = 0;
    struct iphdr *ipHdr = NULL;
    struct ip6_hdr *ip6Hdr = NULL;
    struct tcphdr *tcpHdr = NULL;
    struct udphdr *udpHdr = NULL;
    char *packet_data = NULL;
    unsigned int packet_dataLen = 0;
    char *host_addr = NULL, *useragent_addr = NULL, *method_addr = NULL;
    unsigned int host_len = 0, useragent_len = 0;
    int http_req_fragmented = 0;
    char *hdr_name_addr = NULL, *hdr_value_addr = NULL;
    unsigned int hdr_value_len = 0;
    conntrack_info_t dns_conn_info;
    tcp_conntrack_info_t tcp_conn_info;
    uint8_t should_send_fake = 0;
    unsigned int current_fragment_size = 0;

    /* Determine IP version */
    uint8_t version = (packet[0] >> 4);

    if (version == 4 && packet_len >= sizeof(struct iphdr)) {
        packet_v4 = 1;
        ipHdr = (struct iphdr *)packet;
        unsigned int ip_hdr_len = (unsigned int)ipHdr->ihl * 4;

        if (ipHdr->protocol == IPPROTO_TCP && packet_len >= ip_hdr_len + sizeof(struct tcphdr)) {
            tcpHdr = (struct tcphdr *)(packet + ip_hdr_len);
            unsigned int tcp_hdr_len = (unsigned int)tcpHdr->doff * 4;
            unsigned int total_hdr = ip_hdr_len + tcp_hdr_len;
            if (packet_len > total_hdr) {
                packet_data = (char *)(packet + total_hdr);
                packet_dataLen = (unsigned int)(packet_len - total_hdr);
            }
        }
        else if (ipHdr->protocol == IPPROTO_UDP && packet_len >= ip_hdr_len + sizeof(struct udphdr)) {
            udpHdr = (struct udphdr *)(packet + ip_hdr_len);
            unsigned int total_hdr = ip_hdr_len + sizeof(struct udphdr);
            if (packet_len > total_hdr) {
                packet_data = (char *)(packet + total_hdr);
                packet_dataLen = (unsigned int)(packet_len - total_hdr);
            }
        }
    }
    else if (version == 6 && packet_len >= sizeof(struct ip6_hdr)) {
        packet_v6 = 1;
        ip6Hdr = (struct ip6_hdr *)packet;
        unsigned int ip6_hdr_len = sizeof(struct ip6_hdr);
        uint8_t next_hdr = ip6Hdr->ip6_nxt;

        if (next_hdr == IPPROTO_TCP && packet_len >= ip6_hdr_len + sizeof(struct tcphdr)) {
            tcpHdr = (struct tcphdr *)(packet + ip6_hdr_len);
            unsigned int tcp_hdr_len = (unsigned int)tcpHdr->doff * 4;
            unsigned int total_hdr = ip6_hdr_len + tcp_hdr_len;
            if (packet_len > total_hdr) {
                packet_data = (char *)(packet + total_hdr);
                packet_dataLen = (unsigned int)(packet_len - total_hdr);
            }
        }
        else if (next_hdr == IPPROTO_UDP && packet_len >= ip6_hdr_len + sizeof(struct udphdr)) {
            udpHdr = (struct udphdr *)(packet + ip6_hdr_len);
            unsigned int total_hdr = ip6_hdr_len + sizeof(struct udphdr);
            if (packet_len > total_hdr) {
                packet_data = (char *)(packet + total_hdr);
                packet_dataLen = (unsigned int)(packet_len - total_hdr);
            }
        }
    }

    /* ===== TCP with DATA ===== */
    if (tcpHdr && packet_data && packet_dataLen > 0) {

        /* INBOUND: detect passive DPI redirect */
        if (!is_outbound && packet_dataLen > 16) {
            if (do_passivedpi && is_passivedpi_redirect(packet_data, packet_dataLen)) {
                should_reinject = 0;
            }
        }
        /* OUTBOUND HTTPS: detect TLS ClientHello, send fake */
        else if (is_outbound &&
                ((do_fragment_https ? packet_dataLen == https_fragment_size : 0) ||
                 packet_dataLen > 16) &&
                 ntohs(tcpHdr->dest) != 80 &&
                 (do_fake_packet || do_native_frag))
        {
            if ((packet_dataLen == 2 && memcmp(packet_data, "\x16\x03", 2) == 0) ||
                (packet_dataLen >= 3 && (memcmp(packet_data, "\x16\x03\x01", 3) == 0 ||
                                          memcmp(packet_data, "\x16\x03\x03", 3) == 0)))
            {
                if (do_blacklist || do_fragment_by_sni)
                    sni_ok = extract_sni(packet_data, packet_dataLen, &host_addr, &host_len);

                if ((do_blacklist && sni_ok && blackwhitelist_check_hostname(host_addr, host_len)) ||
                    (do_blacklist && !sni_ok && do_allow_no_sni) ||
                    (!do_blacklist))
                {
                    if (do_fake_packet) {
                        should_send_fake = 1;
                        uint8_t fake_ttl = ttl_of_fake_packet;
                        if (do_auto_ttl || ttl_min_nhops) {
                            if ((packet_v4 && tcp_handle_outgoing((uint32_t[]){ipHdr->saddr,0,0,0}, (uint32_t[]){ipHdr->daddr,0,0,0},
                                    tcpHdr->source, tcpHdr->dest, &tcp_conn_info, 0)) ||
                                (packet_v6 && tcp_handle_outgoing((uint32_t*)&ip6Hdr->ip6_src,
                                    (uint32_t*)&ip6Hdr->ip6_dst,
                                    tcpHdr->source, tcpHdr->dest, &tcp_conn_info, 1)))
                            {
                                if (do_auto_ttl) {
                                    fake_ttl = tcp_get_auto_ttl(tcp_conn_info.ttl, auto_ttl_1,
                                                                 auto_ttl_2, ttl_min_nhops, auto_ttl_max);
                                } else if (ttl_min_nhops) {
                                    if (!tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0))
                                        should_send_fake = 0;
                                }
                            }
                        }
                        if (should_send_fake)
                            send_fake_https_request((const char*)packet, (unsigned int)packet_len,
                                                     packet_v6, fake_ttl, do_wrong_chksum, do_wrong_seq);
                    }
                    if (do_native_frag) should_recalc_checksum = 1;
                }
            }
        }
        /* OUTBOUND HTTP: detect Host header */
        else if (is_outbound && packet_dataLen > 16 &&
                (do_http_allports ? 1 : (ntohs(tcpHdr->dest) == 80)) &&
                find_http_method_end(packet_data, (do_fragment_http ? http_fragment_size : 0u),
                                     &http_req_fragmented) &&
                (do_host || do_host_removespace || do_host_mixedcase ||
                 do_fragment_http_persistent || do_fake_packet))
        {
            if (find_header_and_get_info(packet_data, packet_dataLen,
                http_host_find, &hdr_name_addr, &hdr_value_addr, &hdr_value_len) &&
                hdr_value_len > 0 && hdr_value_len <= HOST_MAXLEN &&
                (do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len) : 1))
            {
                host_addr = hdr_value_addr;
                host_len = hdr_value_len;

                if (do_native_frag) should_recalc_checksum = 1;

                if (do_fake_packet) {
                    should_send_fake = 1;
                    uint8_t fake_ttl = ttl_of_fake_packet;
                    if (do_auto_ttl || ttl_min_nhops) {
                        if ((packet_v4 && tcp_handle_outgoing((uint32_t[]){ipHdr->saddr,0,0,0}, (uint32_t[]){ipHdr->daddr,0,0,0},
                                tcpHdr->source, tcpHdr->dest, &tcp_conn_info, 0)) ||
                            (packet_v6 && tcp_handle_outgoing((uint32_t*)&ip6Hdr->ip6_src,
                                (uint32_t*)&ip6Hdr->ip6_dst,
                                tcpHdr->source, tcpHdr->dest, &tcp_conn_info, 1)))
                        {
                            if (do_auto_ttl) {
                                fake_ttl = tcp_get_auto_ttl(tcp_conn_info.ttl, auto_ttl_1,
                                                             auto_ttl_2, ttl_min_nhops, auto_ttl_max);
                            } else if (ttl_min_nhops) {
                                if (!tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0))
                                    should_send_fake = 0;
                            }
                        }
                    }
                    if (should_send_fake)
                        send_fake_http_request((const char*)packet, (unsigned int)packet_len,
                                                packet_v6, fake_ttl, do_wrong_chksum, do_wrong_seq);
                }

                if (do_host_mixedcase) {
                    mix_case(host_addr, host_len);
                    should_recalc_checksum = 1;
                }
                if (do_host) {
                    memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
                    should_recalc_checksum = 1;
                }
                if (do_additional_space && do_host_removespace) {
                    method_addr = find_http_method_end(packet_data,
                                    (do_fragment_http ? http_fragment_size : 0), NULL);
                    if (method_addr) {
                        memmove(method_addr + 1, method_addr,
                                (size_t)(host_addr - method_addr - 1));
                        should_recalc_checksum = 1;
                    }
                }
                else if (do_host_removespace) {
                    if (find_header_and_get_info(packet_data, packet_dataLen,
                                                http_useragent_find, &hdr_name_addr,
                                                &hdr_value_addr, &hdr_value_len))
                    {
                        useragent_addr = hdr_value_addr;
                        useragent_len = hdr_value_len;
                        if (useragent_addr && useragent_len > 0) {
                            if (useragent_addr > host_addr) {
                                memmove(host_addr - 1, host_addr,
                                        (size_t)(useragent_addr + useragent_len - host_addr));
                                host_addr -= 1;
                                *(char*)((unsigned char*)useragent_addr + useragent_len - 1) = ' ';
                                should_recalc_checksum = 1;
                            } else {
                                memmove(useragent_addr + useragent_len + 1,
                                        useragent_addr + useragent_len,
                                        (size_t)(host_addr - 1 - (useragent_addr + useragent_len)));
                                *(char*)((unsigned char*)useragent_addr + useragent_len) = ' ';
                                should_recalc_checksum = 1;
                            }
                        }
                    }
                }
            }
        }

        /* Native fragmentation */
        if (should_reinject && should_recalc_checksum && do_native_frag) {
            current_fragment_size = 0;
            if (do_fragment_http && ntohs(tcpHdr->dest) == 80)
                current_fragment_size = http_fragment_size;
            else if (do_fragment_https && ntohs(tcpHdr->dest) != 80) {
                if (do_fragment_by_sni && sni_ok)
                    current_fragment_size = (unsigned int)((char*)host_addr - packet_data);
                else
                    current_fragment_size = https_fragment_size;
            }
            if (current_fragment_size) {
                send_native_fragment(packet, (unsigned int)packet_len, packet_data,
                                    packet_dataLen, packet_v4, packet_v6,
                                    ipHdr, ip6Hdr, tcpHdr,
                                    current_fragment_size, do_reverse_frag);
                send_native_fragment(packet, (unsigned int)packet_len, packet_data,
                                    packet_dataLen, packet_v4, packet_v6,
                                    ipHdr, ip6Hdr, tcpHdr,
                                    current_fragment_size, !do_reverse_frag);
                return VERDICT_DROP; /* We sent manually, drop the original */
            }
        }
    }

    /* ===== TCP without DATA (SYN/ACK) ===== */
    else if (tcpHdr && (!packet_data || packet_dataLen == 0)) {
        if (!is_outbound && tcpHdr->syn == 1 && tcpHdr->ack == 1) {
            if (do_fake_packet && (do_auto_ttl || ttl_min_nhops)) {
                if (packet_v4)
                    tcp_handle_incoming((uint32_t[]){ipHdr->saddr,0,0,0}, (uint32_t[]){ipHdr->daddr,0,0,0},
                                       tcpHdr->source, tcpHdr->dest, 0, ipHdr->ttl);
                else if (packet_v6)
                    tcp_handle_incoming((uint32_t*)&ip6Hdr->ip6_src,
                                       (uint32_t*)&ip6Hdr->ip6_dst,
                                       tcpHdr->source, tcpHdr->dest, 1, ip6Hdr->ip6_hlim);
            }
            if (!do_native_frag) {
                if (do_fragment_http && ntohs(tcpHdr->source) == 80) {
                    change_window_size(tcpHdr, http_fragment_size);
                    should_recalc_checksum = 1;
                }
                else if (do_fragment_https && ntohs(tcpHdr->source) != 80) {
                    change_window_size(tcpHdr, https_fragment_size);
                    should_recalc_checksum = 1;
                }
            }
        }
    }

    /* ===== UDP with DATA (DNS) ===== */
    else if (udpHdr && packet_data && packet_dataLen > 0) {
        if ((do_dnsv4_redirect && packet_v4) || (do_dnsv6_redirect && packet_v6)) {
            if (!is_outbound) {
                if ((packet_v4 && dns_handle_incoming((uint32_t[]){ipHdr->daddr,0,0,0}, udpHdr->dest,
                                    packet_data, packet_dataLen, &dns_conn_info, 0)) ||
                    (packet_v6 && dns_handle_incoming((uint32_t*)&ip6Hdr->ip6_dst, udpHdr->dest,
                                    packet_data, packet_dataLen, &dns_conn_info, 1)))
                {
                    if (packet_v4) ipHdr->saddr = dns_conn_info.dstip[0];
                    else if (packet_v6) ipv6_copy_addr((uint32_t*)&ip6Hdr->ip6_src, dns_conn_info.dstip);
                    udpHdr->dest = dns_conn_info.srcport;
                    udpHdr->source = dns_conn_info.dstport;
                    should_recalc_checksum = 1;
                }
                else {
                    if (dns_is_dns_packet(packet_data, packet_dataLen, 0))
                        should_reinject = 0;
                }
            }
            else if (is_outbound) {
                if ((packet_v4 && dns_handle_outgoing((uint32_t[]){ipHdr->saddr,0,0,0}, udpHdr->source,
                                    (uint32_t[]){ipHdr->daddr,0,0,0}, udpHdr->dest,
                                    packet_data, packet_dataLen, 0)) ||
                    (packet_v6 && dns_handle_outgoing((uint32_t*)&ip6Hdr->ip6_src, udpHdr->source,
                                    (uint32_t*)&ip6Hdr->ip6_dst, udpHdr->dest,
                                    packet_data, packet_dataLen, 1)))
                {
                    if (packet_v4) {
                        ipHdr->daddr = dnsv4_addr;
                        udpHdr->dest = dnsv4_port;
                    }
                    else if (packet_v6) {
                        ipv6_copy_addr((uint32_t*)&ip6Hdr->ip6_dst, (uint32_t*)dnsv6_addr.s6_addr);
                        udpHdr->dest = dnsv6_port;
                    }
                    should_recalc_checksum = 1;
                }
                else {
                    if (dns_is_dns_packet(packet_data, packet_dataLen, 1))
                        should_reinject = 0;
                }
            }
        }
    }

    if (!should_reinject)
        return VERDICT_DROP;

    if (should_recalc_checksum)
        recalc_checksums((char *)packet, packet_len);

    return VERDICT_ACCEPT;
}

static void print_usage(void) {
    puts("Usage: goodbyedpi [OPTION...]\n"
    " -p          block passive DPI\n"
    " -q          block QUIC/HTTP3\n"
    " -r          replace Host with hoSt\n"
    " -s          remove space between host header and its value\n"
    " -a          additional space between Method and Request-URI (enables -s)\n"
    " -m          mix Host header case (test.com -> tEsT.cOm)\n"
    " -f <value>  set HTTP fragmentation to value\n"
    " -k <value>  enable HTTP persistent (keep-alive) fragmentation\n"
    " -n          do not wait for first segment ACK when -k is enabled\n"
    " -e <value>  set HTTPS fragmentation to value\n"
    " -w          try to find and parse HTTP traffic on all processed ports\n"
    " -D          run as daemon\n"
    " --port        <value>    additional TCP port to fragment\n"
    " --dns-addr    <value>    redirect UDP DNS to supplied IPv4 address\n"
    " --dns-port    <value>    redirect UDP DNS to supplied port (default 53)\n"
    " --dnsv6-addr  <value>    redirect UDP DNS to supplied IPv6 address\n"
    " --dnsv6-port  <value>    redirect UDP DNS to supplied port (default 53)\n"
    " --dns-verb               print verbose DNS redirection messages\n"
    " --blacklist   <txtfile>  perform tricks only to hosts from supplied file\n"
    " --allow-no-sni           perform circumvention if TLS SNI not detected\n"
    " --frag-by-sni            fragment right before SNI value\n"
    " --set-ttl     <value>    send fake request with supplied TTL\n"
    " --auto-ttl    [a1-a2-m]  auto-detect TTL and decrease it\n"
    " --min-ttl     <value>    minimum TTL distance for fake request\n"
    " --wrong-chksum           send fake request with incorrect TCP checksum\n"
    " --wrong-seq              send fake request with wrong TCP SEQ/ACK\n"
    " --native-frag            fragment by sending smaller packets\n"
    " --reverse-frag           send fragments in reversed order\n"
    " --fake-from-hex <value>  load fake packets from HEX values\n"
    " --fake-with-sni <value>  generate fake packets with given SNI\n"
    " --fake-gen <value>       generate random fake packets\n"
    " --fake-resend <value>    send each fake packet N times\n"
    " --max-payload [value]    skip packets with TCP payload > value\n"
    "\n"
    "PRESETS:\n"
    " -1  -p -r -s -f 2 -k 2 -n -e 2\n"
    " -2  -p -r -s -f 2 -k 2 -n -e 40\n"
    " -3  -p -r -s -e 40\n"
    " -4  -p -r -s\n"
    " -5  -f 2 -e 2 --auto-ttl --reverse-frag --max-payload\n"
    " -6  -f 2 -e 2 --wrong-seq --reverse-frag --max-payload\n"
    " -7  -f 2 -e 2 --wrong-chksum --reverse-frag --max-payload\n"
    " -8  -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload\n"
    " -9  -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q (default)\n");
}

int main(int argc, char *argv[]) {
    int opt;
    bool debug_exit = false;
    int run_as_daemon = 0;

    dnsv4_port = htons(53);
    dnsv6_port = htons(53);

    printf("GoodbyeDPI-Linux " GOODBYEDPI_VERSION
           ": Passive DPI blocker and Active DPI circumvention utility\n"
           "Linux port using NFQUEUE\n\n");

    if (argc == 1) {
        /* Default configuration for Turkish ISPs (-9 --set-ttl 5)
         * Aggressive bypass mode:
         *   - HTTPS/HTTP fragmentation (2 bytes)
         *   - Native fragmentation with reverse order
         *   - Fake packets with TTL=5 (expires before server, fools DPI)
         *   - Fake packets with wrong checksum (dropped by server, fools DPI)
         *   - Fake packets with wrong SEQ (ignored by server, fools DPI)
         *   - Block QUIC (forces HTTPS fallback for better DPI bypass)
         *   - Max payload 1200 (skip large data transfers)
         *
         * Note: DNS redirection is managed externally via system settings
         * (e.g. setup_dns.sh) due to NFQUEUE/conntrack limitations on Linux.
         */
        do_fragment_http = do_fragment_https = 1;
        do_reverse_frag = do_native_frag = 1;
        http_fragment_size = https_fragment_size = 2;
        do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
        do_fake_packet = 1;
        do_wrong_chksum = 1;
        do_wrong_seq = 1;
        do_block_quic = 1;
        max_payload_size = 1200;
        ttl_of_fake_packet = 5;
    }

    while ((opt = getopt_long(argc, argv, "123456789pqrsaf:e:mwk:nD", long_options, NULL)) != -1) {
        switch (opt) {
            case '1':
                do_passivedpi = do_host = do_host_removespace
                = do_fragment_http = do_fragment_https
                = do_fragment_http_persistent
                = do_fragment_http_persistent_nowait = 1;
                break;
            case '2':
                do_passivedpi = do_host = do_host_removespace
                = do_fragment_http = do_fragment_https
                = do_fragment_http_persistent
                = do_fragment_http_persistent_nowait = 1;
                https_fragment_size = 40u;
                break;
            case '3':
                do_passivedpi = do_host = do_host_removespace
                = do_fragment_https = 1;
                https_fragment_size = 40u;
                break;
            case '4':
                do_passivedpi = do_host = do_host_removespace = 1;
                break;
            case '5':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_auto_ttl = 1;
                max_payload_size = 1200;
                break;
            case '6':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_seq = 1;
                max_payload_size = 1200;
                break;
            case '9':
                do_block_quic = 1;
                /* fall through */
            case '8':
                do_wrong_seq = 1;
                /* fall through */
            case '7':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                max_payload_size = 1200;
                break;
            case 'p': do_passivedpi = 1; break;
            case 'q': do_block_quic = 1; break;
            case 'r': do_host = 1; break;
            case 's': do_host_removespace = 1; break;
            case 'a': do_additional_space = 1; do_host_removespace = 1; break;
            case 'm': do_host_mixedcase = 1; break;
            case 'f':
                do_fragment_http = 1;
                if (!http_fragment_size)
                    http_fragment_size = atousi(optarg, "Fragment size error\n");
                break;
            case 'k':
                do_fragment_http_persistent = 1;
                do_native_frag = 1;
                if (!http_fragment_size)
                    http_fragment_size = atousi(optarg, "Fragment size error\n");
                break;
            case 'n':
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                do_native_frag = 1;
                break;
            case 'e':
                do_fragment_https = 1;
                https_fragment_size = atousi(optarg, "Fragment size error\n");
                break;
            case 'w': do_http_allports = 1; break;
            case 'D': run_as_daemon = 1; break;
            case 'd': /* --dns-addr */
            {
                struct in_addr tmp;
                if (inet_pton(AF_INET, optarg, &tmp) == 1 && !do_dnsv4_redirect) {
                    do_dnsv4_redirect = 1;
                    dnsv4_addr = tmp.s_addr;
                    flush_dns_cache();
                } else { puts("DNS address error!"); exit(1); }
                break;
            }
            case '!': /* --dnsv6-addr */
            {
                if (inet_pton(AF_INET6, optarg, &dnsv6_addr) == 1 && !do_dnsv6_redirect) {
                    do_dnsv6_redirect = 1;
                    flush_dns_cache();
                } else { puts("DNS v6 address error!"); exit(1); }
                break;
            }
            case 'g': /* --dns-port */
                if (!do_dnsv4_redirect) { puts("Use --dns-addr first!"); exit(1); }
                dnsv4_port = htons(atousi(optarg, "DNS port error!"));
                break;
            case '@': /* --dnsv6-port */
                if (!do_dnsv6_redirect) { puts("Use --dnsv6-addr first!"); exit(1); }
                dnsv6_port = htons(atousi(optarg, "DNS port error!"));
                break;
            case 'v': do_dns_verb = 1; do_tcp_verb = 1; break;
            case 'b': /* --blacklist */
                do_blacklist = 1;
                if (!blackwhitelist_load_list(optarg)) {
                    printf("Can't load blacklist from file!\n"); exit(1);
                }
                break;
            case ']': do_allow_no_sni = 1; break;
            case '>': do_fragment_by_sni = 1; break;
            case '$': /* --set-ttl */
                do_auto_ttl = auto_ttl_1 = auto_ttl_2 = auto_ttl_max = 0;
                do_fake_packet = 1;
                ttl_of_fake_packet = atoub(optarg, "Set TTL error!");
                break;
            case '[': /* --min-ttl */
                do_fake_packet = 1;
                ttl_min_nhops = atoub(optarg, "Min TTL error!");
                break;
            case '+': /* --auto-ttl */
                do_fake_packet = 1;
                do_auto_ttl = 1;
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg) {
                    char *ac = strdup(optarg);
                    if (strchr(ac, '-')) {
                        char *t = strtok(ac, "-");
                        auto_ttl_1 = atoub(t, "Auto TTL error!");
                        t = strtok(NULL, "-");
                        if (!t) { puts("Auto TTL error!"); exit(1); }
                        auto_ttl_2 = atoub(t, "Auto TTL error!");
                        t = strtok(NULL, "-");
                        if (!t) { puts("Auto TTL error!"); exit(1); }
                        auto_ttl_max = atoub(t, "Auto TTL error!");
                    } else {
                        auto_ttl_2 = atoub(optarg, "Auto TTL error!");
                        auto_ttl_1 = auto_ttl_2;
                    }
                    free(ac);
                }
                break;
            case '%': do_fake_packet = 1; do_wrong_chksum = 1; break;
            case ')': do_fake_packet = 1; do_wrong_seq = 1; break;
            case '*': do_native_frag = 1; do_fragment_http_persistent = 1;
                      do_fragment_http_persistent_nowait = 1; break;
            case '(': do_reverse_frag = 1; do_native_frag = 1;
                      do_fragment_http_persistent = 1;
                      do_fragment_http_persistent_nowait = 1; break;
            case '|': /* --max-payload */
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                max_payload_size = optarg ? atousi(optarg, "Max payload error!") : 1200;
                break;
            case 'u': /* --fake-from-hex */
                if (fake_load_from_hex(optarg))
                    printf("WARNING: bad fake HEX value %s\n", optarg);
                break;
            case '}': /* --fake-with-sni */
                if (fake_load_from_sni(optarg))
                    printf("WARNING: bad domain name for SNI: %s\n", optarg);
                break;
            case 'j': /* --fake-gen */
                if (fake_load_random(atoub(optarg, "Fake gen error!"), 200))
                    puts("WARNING: fake generator failed!");
                break;
            case 't': /* --fake-resend */
                fakes_resend = atoub(optarg, "Fake resend error!");
                break;
            case 'x': debug_exit = true; break;
            default: print_usage(); exit(1);
        }
    }

    /* Set defaults */
    if (!http_fragment_size) http_fragment_size = 2;
    if (!https_fragment_size) https_fragment_size = 2;
    if (!auto_ttl_1) auto_ttl_1 = 1;
    if (!auto_ttl_2) auto_ttl_2 = 4;
    if (do_auto_ttl) {
        if (!ttl_min_nhops) ttl_min_nhops = 3;
        if (!auto_ttl_max) auto_ttl_max = 10;
    }

    printf("Block passive: %d\nBlock QUIC: %d\n"
           "Fragment HTTP: %u\nFragment persistent HTTP: %u\n"
           "Fragment HTTPS: %u\nFragment by SNI: %u\n"
           "Native frag: %d\nReverse frag: %d\n"
           "hoSt: %d\nHost no space: %d\nAdditional space: %d\n"
           "Mix Host: %d\nHTTP AllPorts: %d\n"
           "DNS redirect: %d\nDNSv6 redirect: %d\nAllow no SNI: %d\n"
           "Fake TTL: %s (fixed:%hu auto:%hu-%hu-%hu min-dist:%hu)\n"
           "Wrong chksum: %d\nWrong seq: %d\n"
           "Custom fakes: %d\nFake resend: %d\nMax payload: %hu\n",
           do_passivedpi, do_block_quic,
           (do_fragment_http ? http_fragment_size : 0),
           (do_fragment_http_persistent ? http_fragment_size : 0),
           (do_fragment_https ? https_fragment_size : 0),
           do_fragment_by_sni, do_native_frag, do_reverse_frag,
           do_host, do_host_removespace, do_additional_space,
           do_host_mixedcase, do_http_allports,
           do_dnsv4_redirect, do_dnsv6_redirect, do_allow_no_sni,
           do_auto_ttl ? "auto" : (do_fake_packet ? "fixed" : "disabled"),
           ttl_of_fake_packet, do_auto_ttl ? auto_ttl_1 : 0,
           do_auto_ttl ? auto_ttl_2 : 0, do_auto_ttl ? auto_ttl_max : 0,
           ttl_min_nhops, do_wrong_chksum, do_wrong_seq,
           fakes_count, fakes_resend, max_payload_size);

    if (debug_exit) {
        printf("Debug Exit\n");
        exit(EXIT_SUCCESS);
    }

    /* Check root privileges */
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root (sudo).\n");
        exit(EXIT_FAILURE);
    }

    /* Daemonize if requested */
    if (run_as_daemon) {
        printf("Running as daemon...\n");
        if (service_daemonize() < 0) {
            fprintf(stderr, "Failed to daemonize\n");
            exit(EXIT_FAILURE);
        }
        service_write_pidfile(NULL);
    }

    /* Initialize raw socket for fake packet injection */
    if (do_fake_packet || do_native_frag) {
        if (raw_socket_init() < 0) {
            fprintf(stderr, "Failed to initialize raw socket\n");
            die();
        }
    }

    /* Set up signal handler */
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    /* Open NFQUEUE */
    printf("\nOpening NFQUEUE %d...\n", QUEUE_NUM_MAIN);
    nfq_handles[0] = nfqueue_open(QUEUE_NUM_MAIN, packet_callback, NULL);
    if (!nfq_handles[0]) {
        fprintf(stderr, "Failed to open NFQUEUE %d\n"
                "Make sure iptables rules are set up. Run:\n"
                "  sudo bash setup_iptables.sh\n", QUEUE_NUM_MAIN);
        die();
    }
    nfq_handle_count = 1;

    printf("Filter activated, GoodbyeDPI-Linux is now running!\n");
    printf("Make sure iptables rules are set up. If not, run:\n"
           "  sudo bash setup_iptables.sh\n\n");

    /* Enter main packet processing loop */
    nfqueue_loop(nfq_handles[0]);

    /* Cleanup */
    deinit_all();
    if (run_as_daemon)
        service_remove_pidfile(NULL);

    return 0;
}
